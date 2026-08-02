import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  readJson,
  sha256File,
  sha256Text,
} from "./estate.mjs";

export const GENERATION_FORMAT = "ioi.program.estate_generation.v1";
export const GENERATION_REL = "program/estate-generation.v1.json";
export const CONDITIONS_REL = "program/release-closure-conditions.v1.json";
export const PROMOTIONS_REL = "_archive/attestations/estate-promotions.v1.json";
export const REVIEW_BINDINGS_REL = "_archive/attestations/release-review-bindings.v1.json";
export const RELEASE_ROOT = "_archive/release-candidates/2026-07-29";

function filesUnder(root, rel) {
  const start = path.join(root, rel);
  if (!fs.existsSync(start)) return [];
  if (fs.statSync(start).isFile()) return [rel];
  const out = [];
  const stack = [start];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) out.push(path.relative(root, abs));
    }
  }
  return out.sort();
}

function digestMap(root, rels) {
  return Object.fromEntries(
    [...new Set(rels)].sort().map((rel) => [rel, sha256File(path.join(root, rel))]),
  );
}

function requiredRecords(closure) {
  return (closure.required_successor_work_item_ids ?? []).map((id) => {
    const rel = `work-items/active/${id}.v1.json`;
    const abs = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(abs)) throw new Error(`required evidence-ready record is absent: ${rel}`);
    const record = readJson(abs);
    if (record.status !== "evidence_ready") {
      throw new Error(`${id} is ${record.status}, not evidence_ready`);
    }
    const literalPath = (record.evidence_index?.expected_output_paths ?? [])
      .find((value) => typeof value === "string" && value.endsWith(".exit.v1.txt"));
    if (!literalPath) throw new Error(`${id} declares no literal-exit path`);
    const literalRel = literalPath.replace(/^internal-docs\/implementation\//, "");
    const candidateRel = `${RELEASE_ROOT}/certification/${id}.json`;
    if (!fs.existsSync(path.join(ESTATE_ROOT, literalRel))) throw new Error(`${literalRel} is absent`);
    if (!fs.existsSync(path.join(ESTATE_ROOT, candidateRel))) throw new Error(`${candidateRel} is absent`);
    return { id, record_rel: rel, literal_rel: literalRel, certification_candidate_rel: candidateRel };
  });
}

export function buildReleaseGeneration() {
  const closure = readJson(path.join(ESTATE_ROOT, CONDITIONS_REL));
  const records = requiredRecords(closure);
  const promotionLedger = readJson(path.join(ESTATE_ROOT, PROMOTIONS_REL));
  const promotions = promotionLedger.promotions ?? [];
  const casNames = filesUnder(ESTATE_ROOT, "_archive/evidence/cas")
    .map((rel) => path.basename(rel))
    .sort();

  const immutable = new Set([
    CONDITIONS_REL,
    "source-dispositions.v1.json",
    "stages/m9.md",
    ...filesUnder(ESTATE_ROOT, "tools"),
    ...filesUnder(ESTATE_ROOT, "program").filter((rel) => ![
      GENERATION_REL,
      "program/canon-baseline-successor.v1.json",
      "program/canon-overlay-manifest.v2.json",
    ].includes(rel)),
    ...filesUnder(ESTATE_ROOT, RELEASE_ROOT),
    ...filesUnder(ESTATE_ROOT, "_archive/attestations").filter((rel) => ![
      PROMOTIONS_REL,
      REVIEW_BINDINGS_REL,
    ].includes(rel)),
    ...records.map((record) => record.literal_rel),
  ]);
  const mutable = new Set([
    "NOW.md",
    ...records.map((record) => record.record_rel),
    ...filesUnder(ESTATE_ROOT, "generated"),
    ...filesUnder(ESTATE_ROOT, "_archive/holds"),
  ]);
  const expectedAbsent = [
    "program/canon-baseline-successor.v1.json",
    "program/canon-overlay-manifest.v2.json",
    ...records.map((record) => `evidence/${record.id}.certification.v1.json`),
  ];

  return {
    evidence_format: GENERATION_FORMAT,
    generation_id: "release-successor-repair-2026-07-29-v1",
    state: "frozen_for_independent_review",
    role: "Exact pre-transaction generation for the independently reviewed, atomic successor-admission batch. It binds inputs; it authorizes nothing by itself.",
    created_at: new Date().toISOString(),
    bound_git_tree: {
      commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" }).trim(),
      docs_tree_sha: execFileSync("git", ["rev-parse", "HEAD:docs"], { cwd: REPO_ROOT, encoding: "utf8" }).trim(),
    },
    closure_contract: {
      path: CONDITIONS_REL,
      sha256: sha256File(path.join(ESTATE_ROOT, CONDITIONS_REL)),
      successor_ids: records.map((record) => record.id),
    },
    promotion_prefix: {
      through_sequence: promotions.length,
      head_promotion_id: promotions.at(-1)?.promotion_id ?? null,
      prefix_sha256: sha256Text(JSON.stringify(promotions, null, 2)),
    },
    cas_prefix: {
      object_count: casNames.length,
      object_name_set_sha256: sha256Text(JSON.stringify(casNames)),
      required_objects: casNames,
    },
    successors: records,
    immutable_inputs: digestMap(ESTATE_ROOT, [...immutable]),
    mutable_prestate: digestMap(ESTATE_ROOT, [...mutable]),
    expected_absent_before_transaction: expectedAbsent,
    admitted_outputs: {
      overlay: `${RELEASE_ROOT}/admission/canon-overlay-manifest.v2.json`,
      baseline: `${RELEASE_ROOT}/admission/canon-baseline-successor.v1.json`,
      destination_overlay: "program/canon-overlay-manifest.v2.json",
      destination_baseline: "program/canon-baseline-successor.v1.json",
    },
    transaction: {
      tool: "tools/transition-successor-batch.mjs",
      rule: "All named successors transition from evidence_ready to verified in the declared order; every hold is discharged, admitted overlay/baseline bytes are copied exactly from the frozen candidates, the certification hold closes, every changed estate target is promoted, and check-program must finish with zero errors and zero certification-relevant skips. Any failure restores the prestate and promotion/CAS prefixes.",
    },
    nonclaim: "This generation is a review object, not a review. It changes no status, admits no baseline, closes no hold, and makes no product or release claim.",
  };
}

export function validateReleaseGeneration(generation, { phase = "post" } = {}) {
  const errors = [];
  const add = (message) => errors.push(message);
  if (generation?.evidence_format !== GENERATION_FORMAT) add(`generation format is ${generation?.evidence_format ?? "absent"}`);
  const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  const docs = execFileSync("git", ["rev-parse", "HEAD:docs"], { cwd: REPO_ROOT, encoding: "utf8" }).trim();
  if (generation?.bound_git_tree?.commit !== head || generation?.bound_git_tree?.docs_tree_sha !== docs) {
    add("bound Git commit/docs tree no longer matches the checkout");
  }
  const ledger = readJson(path.join(ESTATE_ROOT, PROMOTIONS_REL));
  const prefixLength = generation?.promotion_prefix?.through_sequence ?? -1;
  const prefix = (ledger.promotions ?? []).slice(0, prefixLength);
  if (prefix.length !== prefixLength || sha256Text(JSON.stringify(prefix, null, 2)) !== generation?.promotion_prefix?.prefix_sha256) {
    add("promotion ledger no longer contains the exact reviewed prefix");
  }
  const currentCas = new Set(filesUnder(ESTATE_ROOT, "_archive/evidence/cas").map((rel) => path.basename(rel)));
  for (const object of generation?.cas_prefix?.required_objects ?? []) {
    if (!currentCas.has(object)) add(`reviewed CAS object is absent: ${object}`);
  }
  for (const [rel, digest] of Object.entries(generation?.immutable_inputs ?? {})) {
    const abs = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(abs)) add(`immutable review input is absent: ${rel}`);
    else if (sha256File(abs) !== digest) add(`immutable review input moved: ${rel}`);
  }
  if (phase === "pre") {
    for (const [rel, digest] of Object.entries(generation?.mutable_prestate ?? {})) {
      const abs = path.join(ESTATE_ROOT, rel);
      if (!fs.existsSync(abs)) add(`mutable prestate input is absent: ${rel}`);
      else if (sha256File(abs) !== digest) add(`mutable prestate input moved before transaction: ${rel}`);
    }
    for (const rel of generation?.expected_absent_before_transaction ?? []) {
      if (fs.existsSync(path.join(ESTATE_ROOT, rel))) add(`pre-transaction-absent target already exists: ${rel}`);
    }
  }
  return errors;
}
