#!/usr/bin/env node
// Read-only validator for the ignored private implementation work-item estate.
// Architecture doctrine stays in canon; private records carry cut status,
// anchors, and proof claims without publishing the implementation queue.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK_ITEMS_DIR = "internal-docs/implementation/work-items";
const M0_LITERAL_EXIT_LOG =
  "internal-docs/implementation/evidence/m0-exit.v1.txt";
const M0_EXIT_REPORT = "docs/evidence/m0-program-control/m0-exit-report.json";
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
const PROPOSED_REQUIRED_ARRAY_FIELDS = [
  "contract_families",
  "dependencies",
  "exit_criteria",
];
const PROPOSED_SUCCESS_EXIT_LITERAL =
  /\b[A-Z][A-Z0-9_]*_EXIT=(?:0|PASS|PASSED|SUCCESS|SUCCEEDED|VERIFIED)\b/u;

const errors = [];
const pending = [];
const fail = (condition, message) => {
  if (!condition) {
    errors.push(message);
  }
};

const dir = path.join(repoRoot, WORK_ITEMS_DIR);
if (!fs.existsSync(dir)) {
  process.stdout.write(
    "work-item check skipped: ignored private implementation estate is absent; no cut or stage status was validated.\n",
  );
  process.exit(0);
}
const files = fs.readdirSync(dir).filter((name) => name.endsWith(".json")).sort();
fail(files.length > 0, "no work-item records found");

const seenIds = new Set();
const recordsById = new Map();
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
  recordsById.set(record.work_item_id, record);
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

  if (record.status === "proposed") {
    for (const field of PROPOSED_REQUIRED_ARRAY_FIELDS) {
      fail(
        Array.isArray(record[field]) &&
          record[field].length > 0 &&
          record[field].every(
            (value) => typeof value === "string" && value.trim().length > 0,
          ),
        `${label} proposed record must have nonempty string array ${field}`,
      );
    }
    fail(
      Array.isArray(record.exit_criteria) &&
        record.exit_criteria.some(
          (criterion) =>
            typeof criterion === "string" && PROPOSED_SUCCESS_EXIT_LITERAL.test(criterion),
        ),
      `${label} proposed record must declare a literal *_EXIT= success contract`,
    );
  }

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

// M0 is the only stage currently projected as verified. Its legacy JSON exit
// report is wrapped by one retained literal exit line whose artifact hash is
// checked here. This does not generalize or close a new bar; the proposed M0
// record still owns the broader literal-exit contract work.
try {
  const log = fs.readFileSync(path.join(repoRoot, M0_LITERAL_EXIT_LOG), "utf8");
  const literalValues = [...log.matchAll(/^M0_EXIT=(.*)$/gmu)].map(
    (match) => match[1],
  );
  fail(
    literalValues.length === 1 && literalValues[0] === "0",
    `${M0_LITERAL_EXIT_LOG} must contain exactly one literal M0_EXIT=0`,
  );
  const artifactRefs = [...log.matchAll(/^ARTIFACT=(.*)$/gmu)].map(
    (match) => match[1],
  );
  fail(
    artifactRefs.length === 1 && artifactRefs[0] === M0_EXIT_REPORT,
    `${M0_LITERAL_EXIT_LOG} must bind ${M0_EXIT_REPORT}`,
  );
  const declaredHashes = [...log.matchAll(/^ARTIFACT_SHA256=([0-9a-f]{64})$/gmu)].map(
    (match) => match[1],
  );
  const reportBytes = fs.readFileSync(path.join(repoRoot, M0_EXIT_REPORT));
  const actualHash = crypto.createHash("sha256").update(reportBytes).digest("hex");
  fail(
    declaredHashes.length === 1 && declaredHashes[0] === actualHash,
    `${M0_LITERAL_EXIT_LOG} does not bind the current M0 exit-report bytes`,
  );
  fail(
    recordsById
      .get("m0-literal-exit-evidence-contract")
      ?.evidence_refs?.includes(M0_LITERAL_EXIT_LOG),
    `m0-literal-exit-evidence-contract must reference ${M0_LITERAL_EXIT_LOG}`,
  );
} catch (error) {
  errors.push(`cannot validate the retained M0 literal exit: ${error.message}`);
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
  `private work-item check passed: ${files.length} records, ${pending.length} pr_open anchors pending in this checkout.\n`,
);
