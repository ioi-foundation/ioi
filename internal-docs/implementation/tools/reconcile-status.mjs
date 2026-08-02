#!/usr/bin/env node
// Reconciles a private work-item record to its declared status authority.
//
//   node tools/reconcile-status.mjs             report divergences only
//   node tools/reconcile-status.mjs --apply     adopt the merged tracked status
//
// This tool exists because status can legitimately advance in a merged, tracked
// record (docs/architecture/_meta/work-items/) while the private mirror still
// holds the pre-merge value. Adopting the merged value is RECONCILIATION, not
// promotion: the source is a merged record on origin/master, and the tool
// records where each adopted value came from.
//
// It only ever copies FROM the tracked authority TO the private mirror, and only
// for records that exist in both. It cannot invent, advance, or regress a status
// that no merged record already carries.
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
  sha256File,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";

const TRACKED_DIR = "docs/architecture/_meta/work-items";

function main() {
  const apply = process.argv.includes("--apply");
  const records = loadWorkItems();
  const findings = [];
  const adopted = [];

  const masterCommit = (() => {
    try {
      return execFileSync("git", ["rev-parse", "origin/master"], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      }).trim();
    } catch {
      return "unknown";
    }
  })();

  for (const record of records) {
    const authority = statusAuthority(record);
    if (authority.owner !== "tracked_merged_record" || authority.agrees) continue;

    const trackedPath = path.join(
      REPO_ROOT,
      TRACKED_DIR,
      `${record.work_item_id}.v1.json`,
    );
    const privatePath = path.join(ESTATE_ROOT, record.file);
    const before = readJson(privatePath);

    findings.push(
      finding(
        apply ? "warn" : "error",
        "status-divergence",
        `${record.work_item_id}: tracked merged record says "${authority.status}", private mirror says "${authority.private_status}"`,
        { work_item_id: record.work_item_id },
      ),
    );

    if (!apply) continue;

    const entry = {
      work_item_id: record.work_item_id,
      private_record: `internal-docs/implementation/${record.file}`,
      private_status_before: before.status,
      private_record_sha256_before: sha256File(privatePath),
      adopted_status: authority.status,
      source_of_record: `${TRACKED_DIR}/${record.work_item_id}.v1.json`,
      source_sha256: sha256File(trackedPath),
      source_merged_at: masterCommit,
    };

    before.status = authority.status;
    before.last_status_transaction = {
      ...(typeof before.last_status_transaction === "object"
        ? before.last_status_transaction
        : {}),
      reconciled_from: entry.source_of_record,
      reconciled_source_sha256: entry.source_sha256,
      reconciled_source_merged_at: masterCommit,
      reconciliation_rule:
        "Adopted from the merged tracked record, which is this cut's declared status authority. No new proof was produced by this reconciliation.",
    };
    writeJsonDeterministic(privatePath, before);
    entry.private_record_sha256_after = sha256File(privatePath);
    adopted.push(entry);
  }

  if (apply) {
    const ledgerPath = path.join(
      ESTATE_ROOT,
      "_archive",
      "migrations",
      "status-reconciliation.v1.json",
    );
    const previous = fs.existsSync(ledgerPath)
      ? readJson(ledgerPath)
      : { evidence_format: "ioi.program.status_reconciliation.v1", entries: [] };
    previous.rule =
      "Each entry records one private mirror adopting the status already carried by its merged tracked authority. Adoption copies a merged value; it never produces proof and never advances a status no merged record holds.";
    previous.entries = [...previous.entries, ...adopted];
    writeJsonDeterministic(ledgerPath, previous);
    process.stdout.write(
      `adopted ${adopted.length} merged status value(s); ledger: _archive/migrations/status-reconciliation.v1.json\n`,
    );
  }

  process.exit(report("reconcile-status", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
