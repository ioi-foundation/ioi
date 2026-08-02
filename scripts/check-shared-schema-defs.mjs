#!/usr/bin/env node
// Byte-identity bar for SHARED architecture-contract $defs.
//
// WHY THIS EXISTS
//
// The contract generator supports only LOCAL `$ref`s ("only local references
// are supported") because each schema must project to Rust and TypeScript on
// its own. A definition that several families need is therefore COPIED into
// each family's `$defs` — and a copy is a drift surface: the moment two copies
// are edited independently, or a third family copies whichever it finds first,
// their CONSTRAINTS can diverge with no check firing. That is how a forgeable
// shape gets introduced without anyone deciding to introduce one.
//
// This bar makes the copies a mechanically enforced single definition: every
// occurrence of a registered shared def must be BYTE-IDENTICAL under canonical
// JSON. Divergence fails, and the failure names every file and the exact
// digest each carries.
//
//   node scripts/check-shared-schema-defs.mjs
//
// Registering a shared def is deliberate: add its name below. An unregistered
// duplicate is not policed — the point is that shared shapes are DECLARED
// shared, not discovered to be.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import process from "node:process";
import { fileURLToPath } from "node:url";

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_DIR = path.join(REPO, "docs", "architecture", "_meta", "schemas");

// Shared defs under byte-identity enforcement, with why each is shared.
const SHARED_DEFS = new Map([
  [
    "agentgresOperationReference",
    "The ADR 0030 reference shape: every chain-bearing value (sequence, root, head, receipt) exists only as a reference to a canonical Agentgres operation. A divergent copy is how a family-owned scalar or a looser ref pattern re-enters.",
  ],
]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

const digest = (value) =>
  crypto.createHash("sha256").update(canonical(value)).digest("hex");

export function collectSharedDefs(schemaDir, readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"))) {
  const found = new Map([...SHARED_DEFS.keys()].map((name) => [name, []]));
  if (!fs.existsSync(schemaDir)) return found;
  for (const entry of fs.readdirSync(schemaDir).sort()) {
    if (!entry.endsWith(".schema.json")) continue;
    let schema;
    try {
      schema = readJson(path.join(schemaDir, entry));
    } catch {
      continue;
    }
    for (const name of SHARED_DEFS.keys()) {
      const def = schema?.$defs?.[name];
      if (def !== undefined) {
        found.get(name).push({ file: entry, digest: digest(def) });
      }
    }
  }
  return found;
}

export function divergenceFailures(found) {
  const failures = [];
  for (const [name, copies] of found) {
    if (copies.length === 0) continue;
    const digests = new Set(copies.map((copy) => copy.digest));
    if (digests.size > 1) {
      failures.push(
        `shared $def "${name}" has ${digests.size} divergent copies:\n` +
          copies
            .map((copy) => `    ${copy.file}: ${copy.digest.slice(0, 16)}`)
            .join("\n") +
          `\n  Why this is enforced: ${SHARED_DEFS.get(name)}`,
      );
    }
  }
  return failures;
}

// Fail-closed self-test: a synthetic divergent pair MUST be rejected, or this
// bar cannot claim it has teeth.
function selfTest() {
  const synthetic = new Map([
    [
      "agentgresOperationReference",
      [
        { file: "a.schema.json", digest: "a".repeat(64) },
        { file: "b.schema.json", digest: "b".repeat(64) },
      ],
    ],
  ]);
  if (divergenceFailures(synthetic).length !== 1) {
    return ["self-test: a synthetic divergent pair was ACCEPTED; this bar has no teeth"];
  }
  const agreeing = new Map([
    [
      "agentgresOperationReference",
      [
        { file: "a.schema.json", digest: "c".repeat(64) },
        { file: "b.schema.json", digest: "c".repeat(64) },
      ],
    ],
  ]);
  if (divergenceFailures(agreeing).length !== 0) {
    return ["self-test: byte-identical copies were REJECTED; this bar refuses the good case"];
  }
  return [];
}

function main() {
  const selfTestFailures = selfTest();
  const found = collectSharedDefs(SCHEMA_DIR);
  const failures = [...selfTestFailures, ...divergenceFailures(found)];
  if (failures.length > 0) {
    for (const failure of failures) console.error(`FAIL: ${failure}`);
    process.exit(1);
  }
  const summary = [...found.entries()]
    .map(([name, copies]) => `${name}=${copies.length} copy/copies byte-identical`)
    .join("; ");
  console.log(`check-shared-schema-defs: PASS (self-test 2/2; ${summary})`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
