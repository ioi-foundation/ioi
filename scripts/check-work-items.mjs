#!/usr/bin/env node
// Read-only validator for docs/architecture/_meta/work-items/ records — the
// single owner of implementation status truth. Doctrine stays in the matrix;
// these records carry status, anchors, and proof claims, and this checker
// keeps them from rotting the way prose status cells do.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK_ITEMS_DIR = "docs/architecture/_meta/work-items";
const MATRIX_FILE = "docs/architecture/_meta/implementation-matrix.md";
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
const REQUIRED_STRING_FIELDS = [
  "work_item_id",
  "stage_id",
  "status",
  "objective",
  "falsifiable_claim",
  "adversarial_or_fault_proof",
  "source_provenance",
  "last_status_transaction",
];

const errors = [];
const pending = [];
const fail = (condition, message) => {
  if (!condition) {
    errors.push(message);
  }
};

const dir = path.join(repoRoot, WORK_ITEMS_DIR);
const files = fs.readdirSync(dir).filter((name) => name.endsWith(".json")).sort();
fail(files.length > 0, "no work-item records found");

const seenIds = new Set();
for (const name of files) {
  const label = `${WORK_ITEMS_DIR}/${name}`;
  let record;
  try {
    record = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
  } catch (error) {
    errors.push(`${label} is not valid JSON: ${error.message}`);
    continue;
  }
  fail(
    record.evidence_format === "ioi.program.work_item.v1",
    `${label} has an unknown evidence_format`,
  );
  for (const field of REQUIRED_STRING_FIELDS) {
    fail(
      typeof record[field] === "string" && record[field].length > 0,
      `${label} lacks required field ${field}`,
    );
  }
  fail(STATUSES.has(record.status), `${label} has unknown status ${record.status}`);
  fail(
    /^(M\d+|WP-[A-Z]+)$/u.test(record.stage_id ?? ""),
    `${label} has malformed stage_id ${record.stage_id}`,
  );
  fail(
    name === `${record.work_item_id}.v1.json`,
    `${label} filename does not match work_item_id`,
  );
  fail(!seenIds.has(record.work_item_id), `${label} duplicates work_item_id`);
  seenIds.add(record.work_item_id);
  fail(
    /^\d{4}-\d{2}-\d{2}$/u.test(record.last_status_transaction ?? ""),
    `${label} last_status_transaction must be an ISO date`,
  );
  fail(
    Number.isInteger(record.pr) || record.pr === null,
    `${label} pr must be an integer or null`,
  );
  fail(
    Array.isArray(record.remaining_nonclaims) && record.remaining_nonclaims.length > 0,
    `${label} must retain explicit nonclaims`,
  );

  for (const owner of record.canon_owners ?? []) {
    fail(
      fs.existsSync(path.join(repoRoot, owner)),
      `${label} canon owner does not exist: ${owner}`,
    );
  }
  for (const ref of record.evidence_refs ?? []) {
    fail(
      fs.existsSync(path.join(repoRoot, ref)),
      `${label} evidence ref does not exist: ${ref}`,
    );
  }

  let mergedAnchors = 0;
  for (const anchor of record.code_anchors ?? []) {
    fail(
      typeof anchor.path === "string" && anchor.path.length > 0,
      `${label} has a code anchor without a path`,
    );
    fail(
      ["merged", "pr_open"].includes(anchor.present_when),
      `${label} anchor ${anchor.path} needs present_when merged|pr_open`,
    );
    const absolute = path.join(repoRoot, anchor.path ?? "");
    const exists = fs.existsSync(absolute);
    if (anchor.present_when === "merged") {
      mergedAnchors += 1;
      fail(exists, `${label} merged anchor does not exist: ${anchor.path}`);
    } else if (!exists) {
      pending.push(`${label}: pr_open anchor not in this checkout: ${anchor.path}`);
      continue;
    }
    if (exists && typeof anchor.must_contain === "string") {
      const source = fs.readFileSync(absolute, "utf8");
      const contains = source.includes(anchor.must_contain);
      if (anchor.present_when === "merged") {
        fail(
          contains,
          `${label} anchor ${anchor.path} no longer contains "${anchor.must_contain}"`,
        );
      } else if (!contains) {
        // The literal rides the held PR branch; this checkout has the
        // pre-PR file. Pending, not failure — promotion to verified
        // requires converting the anchor to merged, which always fails hard.
        pending.push(`${label}: pr_open literal not in this checkout: ${anchor.path} :: "${anchor.must_contain}"`);
      }
    }
  }
  if (record.status === "verified") {
    fail(
      mergedAnchors > 0,
      `${label} is verified but has no merged code anchors to prove it here`,
    );
    fail(
      (record.code_anchors ?? []).every((anchor) => anchor.present_when === "merged"),
      `${label} is verified but still carries pr_open anchors`,
    );
  }
}

// The matrix must reference every record it delegated status to, and no
// record may be orphaned from the matrix pointer convention.
try {
  const matrix = fs.readFileSync(path.join(repoRoot, MATRIX_FILE), "utf8");
  for (const id of seenIds) {
    fail(
      matrix.includes(id),
      `implementation matrix does not reference work item ${id}`,
    );
  }
} catch (error) {
  errors.push(`cannot cross-check the implementation matrix: ${error.message}`);
}

for (const note of pending) {
  process.stdout.write(`pending: ${note}\n`);
}
if (errors.length > 0) {
  process.stderr.write(
    `work-item check failed with ${errors.length} error(s):\n${errors
      .map((message) => `- ${message}`)
      .join("\n")}\n`,
  );
  process.exit(1);
}
process.stdout.write(
  `work-item check passed: ${files.length} records, ${pending.length} pr_open anchors pending in this checkout.\n`,
);
