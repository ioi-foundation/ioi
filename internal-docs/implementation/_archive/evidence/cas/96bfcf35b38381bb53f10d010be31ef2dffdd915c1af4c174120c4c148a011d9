#!/usr/bin/env node
// The machine-checked retained-log contract for literal proof-bar exit values
// (m0-literal-exit-evidence-contract).
//
// Two duties:
//   1. Validate every retained stage-evidence log under evidence/M0..M14/
//      against the ioi.program.literal_exit.v1 contract: content-bound
//      artifact digest, exactly one literal line, success value, nonclaim,
//      no duplicates, not truncated. Workflow evidence stays workflow
//      evidence: a green task process with no literal proves nothing.
//   2. Fail-closed self-test over the PREDECLARED fixture set under
//      fixtures/literal-exit/. Eight classes — missing, duplicate,
//      conflicting, malformed, stale, truncated, non-success, and
//      green-process-no-literal — must every one be rejected for its
//      predeclared reason, or this contract has no teeth.
//
//   node tools/check-literal-exit-contract.mjs
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { ESTATE_ROOT, finding, readJson, report, sha256File } from "./lib/estate.mjs";
import { validateLiteralExitText } from "./lib/literal-exit.mjs";

const EVIDENCE_ROOT = path.join(ESTATE_ROOT, "evidence");
const FIXTURES_DIR = path.join(ESTATE_ROOT, "fixtures", "literal-exit");
const DISPOSITIONS_ABS = path.join(
  ESTATE_ROOT,
  "program",
  "literal-exit-dispositions.v1.json",
);
const STAGE_DIR = /^M\d{1,2}$/;

// The eight predeclared fixture classes. A fixture set missing any class is
// itself a failure: the adversarial branch list is frozen, not discovered.
const REQUIRED_CLASSES = [
  "missing-literal",
  "duplicate-literal",
  "conflicting-literals",
  "malformed-log",
  "stale-artifact-binding",
  "truncated-log",
  "non-success-literal",
  "green-process-no-literal",
];

function workItemStatuses() {
  const out = new Map();
  for (const subdir of ["proposed", "active"]) {
    const dir = path.join(ESTATE_ROOT, "work-items", subdir);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir).filter((name) => name.endsWith(".v1.json"))) {
      const record = readJson(path.join(dir, entry));
      out.set(record.work_item_id, record.status);
    }
  }
  return out;
}

export function evaluateHistoricalDisposition({ disposition, artifactSha256, successorStatus }) {
  if (!disposition) return "no content-bound historical disposition exists";
  if (disposition.artifact_sha256 !== artifactSha256) {
    return `historical disposition binds ${disposition.artifact_sha256}, artifact is ${artifactSha256}`;
  }
  if (successorStatus !== "verified") {
    return `corrective successor ${disposition.successor_work_item_id} is ${successorStatus ?? "absent"}, not verified`;
  }
  return null;
}

function collectStringValues(value, out) {
  if (typeof value === "string") out.add(value);
  else if (Array.isArray(value)) value.forEach((item) => collectStringValues(item, out));
  else if (value && typeof value === "object") {
    Object.values(value).forEach((item) => collectStringValues(item, out));
  }
}

function main() {
  const findings = [];
  const statuses = workItemStatuses();
  const dispositionEntries = fs.existsSync(DISPOSITIONS_ABS)
    ? readJson(DISPOSITIONS_ABS).entries ?? []
    : [];
  const dispositionByPath = new Map(
    dispositionEntries.map((entry) => [entry.artifact_path, entry]),
  );

  // Duty 1: every retained stage log validates.
  let validated = 0;
  if (fs.existsSync(EVIDENCE_ROOT)) {
    for (const dir of fs.readdirSync(EVIDENCE_ROOT).sort()) {
      if (!STAGE_DIR.test(dir)) continue;
      const stageDir = path.join(EVIDENCE_ROOT, dir);
      for (const entry of fs.readdirSync(stageDir).sort()) {
        if (!entry.endsWith(".exit.v1.txt")) continue;
        const abs = path.join(stageDir, entry);
        const defects = validateLiteralExitText(fs.readFileSync(abs, "utf8"));
        validated += 1;
        const artifactPath = `internal-docs/implementation/evidence/${dir}/${entry}`;
        const disposition = dispositionByPath.get(artifactPath);
        const dispositionDefect = defects.length > 0
          ? evaluateHistoricalDisposition({
              disposition,
              artifactSha256: sha256File(abs),
              successorStatus: disposition
                ? statuses.get(disposition.successor_work_item_id)
                : null,
            })
          : null;
        if (defects.length > 0 && dispositionDefect) {
          findings.push(
            finding(
              "error",
              "retained-log",
              `evidence/${dir}/${entry}: ${defects.join(" | ")}; historical disposition not closed: ${dispositionDefect}`,
            ),
          );
        }
      }
    }
  }

  // Legacy top-level evidence predates this log contract, but it is not
  // therefore unexamined. Every file must be named exactly by a work-item
  // record; omission is an error rather than an unconditional SKIP.
  const declaredStrings = new Set();
  for (const subdir of ["proposed", "active"]) {
    const dir = path.join(ESTATE_ROOT, "work-items", subdir);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir).filter((name) => name.endsWith(".v1.json"))) {
      collectStringValues(readJson(path.join(dir, entry)), declaredStrings);
    }
  }
  for (const entry of fs.readdirSync(EVIDENCE_ROOT).sort()) {
    const abs = path.join(EVIDENCE_ROOT, entry);
    if (!fs.statSync(abs).isFile()) continue;
    const rel = `internal-docs/implementation/evidence/${entry}`;
    if (!declaredStrings.has(rel)) {
      findings.push(
        finding(
          "error",
          "top-level-evidence-unregistered",
          `${rel} is retained at the legacy top level but no work-item record names it`,
        ),
      );
    }
  }

  // Duty 2: fail-closed fixture self-test.
  if (!fs.existsSync(FIXTURES_DIR)) {
    findings.push(
      finding("error", "fixture-self-test", `fixtures directory missing: ${FIXTURES_DIR}`),
    );
  } else {
    const manifest = readJson(path.join(FIXTURES_DIR, "manifest.v1.json"));
    const byClass = new Map(manifest.fixtures.map((f) => [f.class, f]));
    for (const cls of REQUIRED_CLASSES) {
      if (!byClass.has(cls)) {
        findings.push(
          finding("error", "fixture-self-test", `predeclared fixture class absent: ${cls}`),
        );
        continue;
      }
      const fixture = byClass.get(cls);
      const abs = path.join(FIXTURES_DIR, fixture.file);
      if (!fs.existsSync(abs)) {
        findings.push(
          finding("error", "fixture-self-test", `${cls}: fixture file missing: ${fixture.file}`),
        );
        continue;
      }
      const text = fs.readFileSync(abs, "utf8");
      const defects = validateLiteralExitText(text, {
        expectLiteral: fixture.expect_literal ?? null,
      });
      if (defects.length === 0) {
        findings.push(
          finding("error", "fixture-self-test", `${cls}: fixture was ACCEPTED; the contract has no teeth`),
        );
      } else if (
        !defects.some((d) => d.startsWith(fixture.expected_defect_prefix))
      ) {
        findings.push(
          finding(
            "error",
            "fixture-self-test",
            `${cls}: rejected, but never for the predeclared reason (${fixture.expected_defect_prefix}); got: ${defects.join(" | ")}`,
          ),
        );
      }
    }
  }

  const selfDisposition = {
    artifact_sha256: "a".repeat(64),
    successor_work_item_id: "fixture-successor",
  };
  const dispositionCases = [
    [null, "a".repeat(64), "verified", "no content-bound"],
    [selfDisposition, "b".repeat(64), "verified", "historical disposition binds"],
    [selfDisposition, "a".repeat(64), "evidence_ready", "not verified"],
  ];
  for (const [disposition, digest, status, expected] of dispositionCases) {
    const defect = evaluateHistoricalDisposition({
      disposition,
      artifactSha256: digest,
      successorStatus: status,
    });
    if (!defect?.includes(expected)) {
      findings.push(
        finding(
          "error",
          "fixture-self-test",
          `historical-disposition rejection ${expected} did not fire`,
        ),
      );
    }
  }
  if (evaluateHistoricalDisposition({
    disposition: selfDisposition,
    artifactSha256: "a".repeat(64),
    successorStatus: "verified",
  }) !== null) {
    findings.push(
      finding("error", "fixture-self-test", "a content-bound disposition with a verified corrective successor was rejected"),
    );
  }

  report("check-literal-exit-contract", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
