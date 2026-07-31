#!/usr/bin/env node
// The ioi.program.work_item.v1 CONTRACT bar (m0-work-item-contract-completeness-and-owner-lint).
//
// Three duties on top of the per-record shape bar:
//   1. Every record validates against the PUBLISHED schema
//      (program/schemas/work-item.v1.schema.json). The schema document is the
//      single source: this tool interprets it and carries no duplicate field
//      list.
//   2. Reference lint: canon owners resolve in the checkout, contract families
//      claiming registry resolution resolve in the architecture contract
//      registry, dependencies name real records (no prose), private artifacts
//      with a path exist, and no record declares a task exit code as proof
//      (workflow-as-product authority).
//   3. Fail-closed self-test: the predeclared bad-record fixtures under
//      fixtures/work-item-contract/ must every one be rejected, or this bar
//      cannot claim its lint has teeth.
//
//   node tools/check-work-item-contract.mjs [--write-report]
//
// --write-report regenerates generated/work-item-contract-report.v1.json (the
// migration/waiver report). The report is derived, deterministic output; the
// check itself never depends on it.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
  sha256File,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import { applyWaivers, validateRecord, waivers } from "./check-work-item-shape.mjs";

const SCHEMA_PATH = path.join(
  ESTATE_ROOT,
  "program",
  "schemas",
  "work-item.v1.schema.json",
);
const REGISTRY_PATH = path.join(
  REPO_ROOT,
  "docs",
  "architecture",
  "_meta",
  "schemas",
  "architecture-contract-registry.v1.json",
);
const FIXTURES_DIR = path.join(ESTATE_ROOT, "fixtures", "work-item-contract");

function listRecords() {
  const roots = ["work-items/proposed", "work-items/active", "work-items"];
  const seen = new Map();
  for (const root of roots) {
    const dir = path.join(ESTATE_ROOT, root);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir)) {
      if (!entry.endsWith(".v1.json")) continue;
      const abs = path.join(dir, entry);
      if (!fs.statSync(abs).isFile()) continue;
      seen.set(entry, abs);
    }
  }
  return [...seen.values()].sort();
}

// --- A minimal, honest interpreter for the subset of JSON Schema the
// published contract uses: required, const, enum, type, pattern, items,
// properties, maxItems, minLength, oneOf. Unknown keywords are a defect in
// the schema, not silently ignored.
const KNOWN = new Set([
  "$schema",
  "$id",
  "$comment",
  "title",
  "description",
  "type",
  "required",
  "properties",
  "items",
  "pattern",
  "enum",
  "const",
  "maxItems",
  "minLength",
  "oneOf",
]);

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

export function validateAgainstSchema(schema, value, at = "$") {
  const out = [];
  for (const key of Object.keys(schema)) {
    if (!KNOWN.has(key)) out.push(`${at}: schema uses unknown keyword ${key}`);
  }
  if (schema.oneOf) {
    const branches = schema.oneOf.map((b) => validateAgainstSchema(b, value, at));
    if (!branches.some((b) => b.length === 0)) {
      out.push(
        `${at}: matches no oneOf branch (${
          branches.map((b) => b[0] ?? "ok").join(" | ")
        })`,
      );
    }
    return out;
  }
  if (schema.const !== undefined && value !== schema.const) {
    out.push(`${at}: expected const ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    out.push(`${at}: ${JSON.stringify(value)} not in enum`);
  }
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = typeOf(value);
    const ok = types.some((t) =>
      t === actual || (t === "integer" && actual === "number" && Number.isInteger(value))
    );
    if (!ok) out.push(`${at}: expected type ${types.join("|")}, got ${actual}`);
  }
  if (typeOf(value) === "string") {
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) {
      out.push(`${at}: ${JSON.stringify(value)} fails pattern ${schema.pattern}`);
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      out.push(`${at}: shorter than minLength ${schema.minLength}`);
    }
  }
  if (typeOf(value) === "array") {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      out.push(`${at}: more than maxItems ${schema.maxItems}`);
    }
    if (schema.items) {
      value.forEach((item, i) => {
        out.push(...validateAgainstSchema(schema.items, item, `${at}[${i}]`));
      });
    }
  }
  if (typeOf(value) === "object") {
    for (const req of schema.required ?? []) {
      if (value[req] === undefined) out.push(`${at}: missing required ${req}`);
    }
    for (const [prop, sub] of Object.entries(schema.properties ?? {})) {
      if (value[prop] !== undefined) {
        out.push(...validateAgainstSchema(sub, value[prop], `${at}.${prop}`));
      }
    }
  }
  return out;
}

// --- Reference lint beyond the schema.
export function referenceLint(record, { recordIds, registryContractIds }) {
  const out = [];
  const id = record.work_item_id ?? "(unknown)";

  for (const owner of record.canon_owners ?? []) {
    if (!fs.existsSync(path.join(REPO_ROOT, owner))) {
      out.push(
        finding("error", "owner-resolution", `${id}: canon owner does not resolve: ${owner}`),
      );
    }
  }
  for (const dep of record.dependency_work_item_ids ?? []) {
    if (typeof dep !== "string" || /\s/.test(dep)) {
      out.push(
        finding("error", "prose-dependency", `${id}: dependency is prose, not a record id: ${JSON.stringify(dep)}`),
      );
    } else if (!recordIds.has(dep)) {
      out.push(
        finding("error", "unknown-dependency", `${id}: dependency names no record: ${dep}`),
      );
    }
  }
  for (const family of record.contract_families ?? []) {
    if (family.registry_resolution !== "architecture_contract_registry") continue;
    const ids = family.contract_ids ?? [];
    if (ids.length === 0) {
      out.push(
        finding(
          "error",
          "unresolved-contract-family",
          `${id}: family ${family.name} claims registry resolution with no contract_ids`,
        ),
      );
    }
    for (const cid of ids) {
      if (!registryContractIds.has(cid)) {
        out.push(
          finding(
            "error",
            "unresolved-contract-family",
            `${id}: family ${family.name} names unregistered contract ${cid}`,
          ),
        );
      }
    }
  }
  for (const artifact of record.private_artifacts ?? []) {
    if (artifact?.path && !fs.existsSync(path.join(REPO_ROOT, artifact.path))) {
      out.push(
        finding("error", "private-artifact", `${id}: private artifact path does not resolve: ${artifact.path}`),
      );
    }
  }
  const ei = record.evidence_index;
  if (ei && !Array.isArray(ei) && ei.task_exit_code_is_proof === true) {
    out.push(
      finding("error", "workflow-authority", `${id}: declares a task exit code as proof; workflow evidence is never product authority`),
    );
  }
  if (Array.isArray(ei) && !["proposed", "scoped"].includes(record.status)) {
    out.push(
      finding(
        "error",
        "status-inference",
        `${id}: status ${record.status} with a bare-array evidence_index; evidence-bearing statuses require the object form so status can never be inferred from workflow context`,
      ),
    );
  }
  return out;
}

function lintRecord(record, refs, schema) {
  const out = [...validateRecord(record)];
  const id = record.work_item_id ?? "(unknown)";
  for (const defect of validateAgainstSchema(schema, record)) {
    out.push(finding("error", "schema", `${id}: ${defect}`));
  }
  out.push(...referenceLint(record, refs));
  return out;
}

function main() {
  const writeReport = process.argv.includes("--write-report");
  const findings = [];
  const schema = readJson(SCHEMA_PATH);
  const registry = readJson(REGISTRY_PATH);
  const registryContractIds = new Set(
    registry.contracts.map((c) => c.contract_id),
  );

  const files = listRecords();
  const records = files.map((abs) => ({ abs, record: readJson(abs) }));
  const recordIds = new Set(records.map((r) => r.record.work_item_id));
  const refs = { recordIds, registryContractIds };

  const perRecord = [];
  for (const { abs, record } of records) {
    const raw = lintRecord(record, refs, schema);
    findings.push(...raw);
    perRecord.push({
      work_item_id: record.work_item_id,
      status: record.status,
      record_sha256: sha256File(abs),
      error_count: raw.filter((f) => f.level === "error").length,
    });
  }

  // Fail-closed self-test: every predeclared bad fixture must be rejected.
  const fixtureOutcomes = [];
  if (!fs.existsSync(FIXTURES_DIR)) {
    findings.push(
      finding("error", "fixture-self-test", `fixtures directory missing: ${FIXTURES_DIR}`),
    );
  } else {
    for (const entry of fs.readdirSync(FIXTURES_DIR).sort()) {
      if (!entry.endsWith(".json")) continue;
      const fixture = readJson(path.join(FIXTURES_DIR, entry));
      const raw = lintRecord(fixture.record, refs, schema);
      const errors = raw.filter((f) => f.level === "error");
      const rejected = errors.length > 0;
      const rightReason = errors.some((f) => f.check === fixture.expected_check);
      fixtureOutcomes.push({
        fixture: entry,
        expected_check: fixture.expected_check,
        rejected,
        rejected_for_expected_check: rightReason,
      });
      if (!rejected) {
        findings.push(
          finding("error", "fixture-self-test", `${entry}: bad fixture was ACCEPTED; the lint has no teeth`),
        );
      } else if (!rightReason) {
        findings.push(
          finding(
            "error",
            "fixture-self-test",
            `${entry}: rejected, but never for the predeclared check ${fixture.expected_check} (got: ${
              [...new Set(errors.map((f) => f.check))].join(", ")
            })`,
          ),
        );
      }
    }
    if (fixtureOutcomes.length < 6) {
      findings.push(
        finding("error", "fixture-self-test", `only ${fixtureOutcomes.length} fixtures; the predeclared set requires at least 6`),
      );
    }
  }

  const applied = applyWaivers(findings);

  if (writeReport) {
    const activeWaivers = new Set(
      applied.filter((f) => f.waiver).map((f) => f.waiver),
    );
    writeJsonDeterministic(
      path.join(ESTATE_ROOT, "generated", "work-item-contract-report.v1.json"),
      {
        format: "ioi.program.work_item_contract_report.v1",
        role:
          "Derived migration/waiver report for the ioi.program.work_item.v1 contract bar. Generated output; never authority and never status truth.",
        schema_sha256: sha256File(SCHEMA_PATH),
        record_count: perRecord.length,
        records: perRecord,
        fixture_outcomes: fixtureOutcomes,
        active_waivers: [...activeWaivers].sort().map((id) => {
          const w = waivers().gaps.find((g) => g.id === id);
          return { id, closes_when: w?.closes_when ?? null };
        }),
        error_count: applied.filter((f) => f.level === "error").length,
      },
    );
  }

  report("check-work-item-contract", applied);
  process.exit(applied.some((f) => f.level === "error") ? 1 : 0);
}

main();
