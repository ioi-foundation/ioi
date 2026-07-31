#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { ESTATE_ROOT, finding, readJson, report } from "./lib/estate.mjs";

function recordsUnder(root) {
  const out = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const absolute = path.join(root, entry.name);
    if (entry.isDirectory()) out.push(...recordsUnder(absolute));
    else if (entry.isFile() && entry.name.endsWith(".json")) {
      try {
        const value = readJson(absolute);
        if (value.evidence_format === "ioi.program.work_item.v1") out.push(value);
      } catch {}
    }
  }
  return out;
}

const findings = [];
const sequence = readJson(path.join(ESTATE_ROOT, "program/sequence.v1.json"));
const records = recordsUnder(path.join(ESTATE_ROOT, "work-items"));
const byId = new Map();
for (const record of records) {
  const prior = byId.get(record.work_item_id) ?? [];
  prior.push(record);
  byId.set(record.work_item_id, prior);
}
for (const rung of sequence.claim_ladder) {
  if (!["P1", "P2", "P3"].includes(rung.id)) continue;
  const id = rung.closing_work_item_id;
  if (!id) {
    findings.push(finding("error", "claim-rung-closure", `${rung.id} has no closing_work_item_id`));
    continue;
  }
  const matches = byId.get(id) ?? [];
  if (matches.length !== 1) {
    findings.push(finding("error", "claim-rung-closure", `${rung.id} closing record ${id} resolves ${matches.length} times`));
    continue;
  }
  const record = matches[0];
  if (record.record_role !== "aggregate_exit") {
    findings.push(finding("error", "claim-rung-closure", `${rung.id} closing record ${id} is ${record.record_role}, not aggregate_exit`));
  }
  if (!Array.isArray(record.dependency_work_item_ids) || record.dependency_work_item_ids.length === 0) {
    findings.push(finding("error", "claim-rung-closure", `${rung.id} closing record ${id} has no exact dependency join`));
  }
  if (!record.evidence_index?.literal_exit) {
    findings.push(finding("error", "claim-rung-closure", `${rung.id} closing record ${id} has no literal exit`));
  }
}
process.exit(report("claim-rung-closures", findings, { json: process.argv.includes("--json") }));
