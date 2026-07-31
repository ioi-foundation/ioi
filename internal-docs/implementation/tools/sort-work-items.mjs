#!/usr/bin/env node
// Keeps work-item records filed by whether they are active.
//
//   node tools/sort-work-items.mjs           report misfiled records
//   node tools/sort-work-items.mjs --write   move them
//   node tools/sort-work-items.mjs --write --work-item <id>
//                                           move only that transaction target
//
// `proposed/` holds records that have not started; `active/` holds everything
// that has. The split exists so the handful of records an implementer can act on
// are not buried among the hundred-plus that describe later horizons. Filing is
// derived from the record's status authority, never asserted, and
// tools/transition.mjs re-files as part of its transaction.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  finding,
  report,
  singletonOption,
} from "./lib/estate.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";

function main() {
  const write = process.argv.includes("--write");
  const selector = singletonOption(process.argv.slice(2), "--work-item");
  if (selector.error) {
    process.stderr.write(`${selector.error}\n`);
    process.exit(2);
  }
  const findings = [];
  let moved = 0;
  const allRecords = loadWorkItems();
  if (
    selector.present &&
    !allRecords.some((record) => record.work_item_id === selector.value)
  ) {
    process.stderr.write(`unknown work item: ${selector.value}\n`);
    process.exit(2);
  }
  const records = selector.present
    ? allRecords.filter((record) => record.work_item_id === selector.value)
    : allRecords;

  for (const dir of ["active", "proposed"]) {
    fs.mkdirSync(path.join(ESTATE_ROOT, "work-items", dir), { recursive: true });
  }

  for (const record of records) {
    const status = statusAuthority(record).status;
    const wanted = status === "proposed" ? "proposed" : "active";
    const base = path.basename(record.file);
    const target = `work-items/${wanted}/${base}`;
    if (record.file === target) continue;
    findings.push(
      finding(
        write ? "warn" : "error",
        "work-item-filing",
        `${record.work_item_id} (${status}) is filed at ${record.file}, expected ${target}`,
      ),
    );
    if (!write) continue;
    fs.renameSync(
      path.join(ESTATE_ROOT, record.file),
      path.join(ESTATE_ROOT, target),
    );
    moved += 1;
  }

  if (write) process.stdout.write(`filed ${moved} record(s)\n`);
  process.exit(report("sort-work-items", findings.filter((f) => f.level === "error")));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
