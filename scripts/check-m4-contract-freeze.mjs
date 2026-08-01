#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaRoot = path.join(root, "docs/architecture/_meta/schemas");
const registryPath = path.join(schemaRoot, "architecture-contract-registry.v1.json");
const manifestPath = path.join(
  root,
  "internal-docs/implementation/program/m4-contract-freeze.v1.json",
);
const recordPaths = [
  "internal-docs/implementation/work-items/active/m4-outcome-room-system-spine.v1.json",
  "internal-docs/implementation/work-items/active/m4-room-graph-truth-and-product-projection.v1.json",
];

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function canonical(value) {
  return `${JSON.stringify(stable(value), null, 2)}\n`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function fileCommitment(relativePath) {
  const absolutePath = path.join(schemaRoot, relativePath);
  if (!fs.existsSync(absolutePath)) throw new Error(`frozen contract artifact is missing: ${relativePath}`);
  return { path: relativePath, sha256: sha256(fs.readFileSync(absolutePath)) };
}

export function buildFreezeSnapshot() {
  const records = recordPaths.map((relativePath) => ({
    relativePath,
    body: readJson(relativePath),
  }));
  const contractIds = [...new Set(records.flatMap(({ body }) =>
    (body.contract_families ?? []).flatMap((family) => family.contract_ids ?? []),
  ))].sort();
  if (contractIds.length === 0) throw new Error("M4 contract freeze derived an empty family set");

  const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
  const byId = new Map(registry.contracts.map((entry) => [entry.contract_id, entry]));
  const contracts = contractIds.map((contractId) => {
    const entry = byId.get(contractId);
    if (entry === undefined) throw new Error(`M4 frozen contract is absent from registry: ${contractId}`);
    const fixtures = [
      ...(entry.positive_fixture_refs ?? []),
      ...(entry.negative_fixture_refs ?? []).map((fixture) => fixture.path),
    ].sort().map(fileCommitment);
    const invariants = (entry.cross_field_invariant_refs ?? [])
      .map((invariant) => invariant.path)
      .sort()
      .map(fileCommitment);
    return {
      contract_id: contractId,
      canonical_name: entry.canonical_name,
      registry_entry_sha256: sha256(canonical(entry)),
      schema: fileCommitment(entry.schema_ref),
      invariants,
      fixtures,
    };
  });

  return {
    evidence_format: "ioi.program.m4_contract_freeze.v1",
    rule: "While either source M4 record is not verified, additions are allowed but every derived frozen contract registry entry, schema, invariant, and fixture must remain byte-identical.",
    source_records: records.map(({ relativePath, body }) => ({
      path: relativePath,
      work_item_id: body.work_item_id,
    })),
    derived_contract_count: contractIds.length,
    derived_contract_ids: contractIds,
    contracts,
  };
}

function m4IsOpen() {
  return recordPaths.some((relativePath) => readJson(relativePath).status !== "verified");
}

function mismatch(expected, actual) {
  return canonical(expected) === canonical(actual) ? null :
    "M4 is open and its mechanically derived contract surface changed. Add unrelated families freely, but restore the frozen family or finish/review M4 before changing it.";
}

const writing = process.argv.includes("--write");
const checking = process.argv.includes("--check");
if (writing === checking) {
  console.error("Usage: node scripts/check-m4-contract-freeze.mjs (--write | --check)");
  process.exit(2);
}

const actual = buildFreezeSnapshot();
if (writing) {
  fs.writeFileSync(manifestPath, canonical(actual));
  console.log(`Wrote M4 contract freeze: ${actual.derived_contract_count} contract(s).`);
} else if (!m4IsOpen()) {
  console.log("M4 contract freeze inactive: both source records are verified.");
} else {
  const expected = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const failure = mismatch(expected, actual);
  if (failure !== null) {
    console.error(failure);
    process.exit(1);
  }
  const tampered = structuredClone(actual);
  tampered.contracts[0].schema.sha256 = "0".repeat(64);
  if (mismatch(expected, tampered) === null) {
    throw new Error("M4 freeze self-test failed to detect a frozen schema change");
  }
  console.log(`M4 contract freeze passed: ${actual.derived_contract_count} contract(s) unchanged.`);
}
