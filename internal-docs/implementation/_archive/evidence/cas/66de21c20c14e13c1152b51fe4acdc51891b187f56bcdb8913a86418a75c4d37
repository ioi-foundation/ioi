#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { ESTATE_ROOT, readJson, writeJsonDeterministic } from "./lib/estate.mjs";

const outputPath = path.join(ESTATE_ROOT, "generated", "canon-gap-projection.v1.json");
const snapshot = readJson(path.join(ESTATE_ROOT, "program", "canon-gaps.v1.json"));
const dispositions = readJson(path.join(ESTATE_ROOT, "program", "canon-gap-dispositions.v1.json"));
const known = readJson(path.join(ESTATE_ROOT, "program", "known-gaps.v1.json"));
const canonMap = readJson(path.join(ESTATE_ROOT, "program", "canon-map.v1.json"));
const current = canonMap.subjects
  .filter((subject) => ["unresolved_canon_gap", "missing_implementation_coverage"].includes(subject.classification))
  .map((subject) => ({
    subject_id: subject.id,
    classification: subject.classification,
    reason: subject.reason,
    stages: subject.stages ?? [],
    work_items: subject.work_items ?? [],
  }));
const openKnown = known.gaps
  .filter((gap) => gap.status !== "closed")
  .map((gap) => ({ id: gap.id, check: gap.check, subjects: gap.subjects, closes_when: gap.closes_when }));
const projection = {
  format: "ioi.program.canon_gap_projection.v1",
  role: "Generated orientation only. program/canon-map.v1.json owns current subject classifications; program/canon-gaps.v1.json is an immutable dated discovery snapshot; program/canon-gap-dispositions.v1.json owns later dispositions against snapshots or stage prose; program/known-gaps.v1.json owns explicit checker waivers. This projection changes none of them and is not a second gap authority.",
  sources: {
    current_classification_owner: "program/canon-map.v1.json",
    historical_snapshot: "program/canon-gaps.v1.json",
    disposition_ledger: "program/canon-gap-dispositions.v1.json",
    checker_waiver_owner: "program/known-gaps.v1.json"
  },
  historical_snapshot: {
    found_at_commit: snapshot.found_at_commit,
    found_on: snapshot.found_on,
    gap_count: snapshot.gap_count,
    immutable: true
  },
  disposition_count: dispositions.dispositions.length,
  current_gap_count: current.length,
  current_gaps: current,
  open_checker_waiver_count: openKnown.length,
  open_checker_waivers: openKnown
};
const rendered = `${JSON.stringify(projection, null, 2)}\n`;
if (process.argv.includes("--check")) {
  const actual = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, "utf8") : "";
  if (actual !== rendered) {
    console.error("generated/canon-gap-projection.v1.json is stale; run tools/generate-canon-gap-projection.mjs --write");
    process.exit(1);
  }
  console.log(`canon-gap-projection: PASS (${current.length} current classified gaps; ${openKnown.length} open checker waivers)`);
} else if (process.argv.includes("--write")) {
  writeJsonDeterministic(outputPath, projection);
  console.log("wrote generated/canon-gap-projection.v1.json");
} else {
  console.error("usage: node tools/generate-canon-gap-projection.mjs --check|--write");
  process.exit(2);
}
