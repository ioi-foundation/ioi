#!/usr/bin/env node
// Refreshes each work-item record's canon_snapshot against the current checkout.
//
//   node tools/refresh-canon-snapshots.mjs           report drift only
//   node tools/refresh-canon-snapshots.mjs --write    rewrite the snapshots
//   node tools/refresh-canon-snapshots.mjs --write-unverified
//                                                    re-anchor only records
//                                                    that are not verified
//   --work-item <id>                                 bound the operation to
//                                                    one reviewed record
//
// A record's canon_snapshot is PROVENANCE — "this is the canon revision the
// author read" — not a drift detector. Drift detection belongs to
// tools/canon-impact.mjs, which owns one baseline over the whole canon universe
// instead of 122 separately synchronised per-record registries.
//
// A canon owner that no longer exists is NEVER silently dropped: dropping it
// would narrow the record's declared scope. It is retained with a null digest
// and reported as an error, because a record citing a canon owner that is not in
// the merged tree is a real defect in the record.
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
  sha256Text,
  singletonOption,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import { loadWorkItems } from "./generate-now.mjs";
import { applyWaivers } from "./check-work-item-shape.mjs";

// Exported so the transition regression can exercise the exact write policy
// without mutating the live estate. A selected operation is incapable of
// writing any other record, verified or unverified; --write-unverified also
// refuses to restamp a verified target.
export function canonSnapshotWritePermitted(record, {
  selectedWorkItem = null,
  write = false,
  writeUnverified = false,
} = {}) {
  if (!write) return false;
  if (selectedWorkItem && record.work_item_id !== selectedWorkItem) return false;
  if (writeUnverified && record.status === "verified") return false;
  return true;
}

function main() {
  const writeUnverified = process.argv.includes("--write-unverified");
  const write = process.argv.includes("--write") || writeUnverified;
  const selector = singletonOption(process.argv.slice(2), "--work-item");
  if (selector.error) {
    process.stderr.write(`${selector.error}\n`);
    process.exit(2);
  }
  const selectedWorkItem = selector.value;
  const allRecords = loadWorkItems();
  if (
    selector.present &&
    !allRecords.some((record) => record.work_item_id === selectedWorkItem)
  ) {
    process.stderr.write(`unknown work item: ${selectedWorkItem}\n`);
    process.exit(2);
  }
  const records = allRecords.filter((record) =>
    !selectedWorkItem || record.work_item_id === selectedWorkItem
  );
  const findings = [];
  let refreshed = 0;
  let written = 0;
  let unchanged = 0;
  const missingOwners = new Map();

  const commit = (() => {
    try {
      return execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      }).trim();
    } catch {
      return "unknown";
    }
  })();
  const today = new Date(
    fs.statSync(path.join(ESTATE_ROOT, "program", "sequence.v1.json")).mtime,
  ).toISOString().slice(0, 10);

  for (const record of records) {
    const owners = (record.canon_owners ?? []).map((o) =>
      typeof o === "string" ? o : (o?.path ?? String(o))
    );
    const rows = [];
    let drifted = false;
    const previous = new Map(
      (record.canon_snapshot?.owners ?? []).map((o) => [o.path, o.sha256]),
    );
    for (const owner of owners) {
      const absolute = path.join(REPO_ROOT, owner);
      if (!fs.existsSync(absolute)) {
        rows.push({ path: owner, sha256: null, missing_in_checkout: true });
        drifted = drifted || previous.get(owner) !== undefined;
        const list = missingOwners.get(owner) ?? [];
        list.push(record.work_item_id);
        missingOwners.set(owner, list);
        continue;
      }
      const digest = sha256File(absolute);
      rows.push({ path: owner, sha256: digest });
      if (previous.get(owner) !== digest) drifted = true;
    }
    if (!drifted) {
      unchanged += 1;
      continue;
    }
    refreshed += 1;
    if (!canonSnapshotWritePermitted(record, {
      selectedWorkItem,
      write,
      writeUnverified,
    })) continue;
    written += 1;

    const absolute = path.join(ESTATE_ROOT, record.file);
    const full = readJson(absolute);
    full.canon_snapshot = {
      captured_at: today,
      captured_at_commit: commit,
      snapshot_role:
        "Provenance for the canon revision this record was authored against. Drift detection is owned by generated/canon-baseline.v1.json via tools/canon-impact.mjs.",
      aggregate_sha256: sha256Text(
        JSON.stringify(rows.map((r) => [r.path, r.sha256])),
      ),
      owners: rows,
    };
    writeJsonDeterministic(absolute, full);
  }

  for (const [owner, ids] of [...missingOwners].sort()) {
    findings.push(
      finding(
        "error",
        "canon-owner-missing",
        `canon owner does not exist in this checkout: ${owner} (cited by ${ids.length} record(s): ${
          ids.slice(0, 4).join(", ")
        }${ids.length > 4 ? ", …" : ""})`,
        { owner, work_item_ids: ids },
      ),
    );
  }

  process.stdout.write(
    `${write ? `detected ${refreshed} drifted record(s); wrote ${written}` : `would refresh ${refreshed}`} record(s); ${unchanged} already current\n`,
  );
  process.exit(report("refresh-canon-snapshots", applyWaivers(findings)));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
