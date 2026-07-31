#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  failWith,
  implementationRoot,
  readJson,
} from "./lib.mjs";
import { inspectContentBoundLiteralEvidence } from "./content-bound-literal.mjs";

const errors = [];
const skips = [];
const files = fs.readdirSync(path.join(implementationRoot, "work-items")).filter((name) => name.endsWith(".v1.json")).sort();
for (const name of files) {
  const record = readJson(path.join(implementationRoot, "work-items", name));
  const literal = record.evidence_index?.literal_exit;
  if (!/^[A-Z][A-Z0-9_]*_EXIT=0$/u.test(literal ?? "")) {
    errors.push(`${name}: malformed evidence-index literal exit`);
    continue;
  }
  const literalEvidence = [];
  for (const ref of record.evidence_refs ?? []) {
    const inspected = inspectContentBoundLiteralEvidence(ref, literal);
    if (inspected.has_literal) literalEvidence.push(inspected);
  }
  const expectedOutputPaths = new Set(record.evidence_index?.expected_output_paths ?? []);
  const validEvidence = literalEvidence.filter((entry) => entry.content_bound && expectedOutputPaths.has(entry.ref));
  const invalidEvidence = literalEvidence.filter((entry) => !entry.content_bound || !expectedOutputPaths.has(entry.ref));
  if (record.status === "verified" && (validEvidence.length !== 1 || invalidEvidence.length > 0)) {
    if (
      literalEvidence.length === 0
      && record.evidence_index?.checkout_validation === "legacy_status_unavailable_in_this_checkout"
      && record.evidence_index?.historical_status_preserved === true
    ) {
      skips.push({ work_item_id: record.work_item_id, reason: "retained literal is unavailable or does not bind this recognized older checkout", expected_literal: literal });
    } else {
      errors.push(`${name}: verified status requires exactly one expected-path, content-bound ${literal}; found ${validEvidence.length}`);
      for (const entry of invalidEvidence) {
        errors.push(`${name}: ${entry.ref} is not admissible literal evidence: ${entry.content_bound ? "ref is outside evidence_index.expected_output_paths" : entry.reason}`);
      }
    }
  }
  if (record.status !== "verified" && literalEvidence.length > 0) errors.push(`${name}: non-verified record references a successful exit literal ${literal}`);
}
for (const skip of skips) process.stdout.write(`${JSON.stringify({ result: "SKIP", check: "literal-exit", ...skip, nonclaim: "SKIP preserves the pre-existing status but does not verify it in this checkout" })}\n`);
failWith("literal-exit check", errors);
process.stdout.write(`literal-exit check passed with ${skips.length} explicit checkout SKIP nonclaim(s); only expected-path literals bound to exact artifact bytes or a committed artifact identity count as proof, and task/process exit codes were not inspected\n`);
