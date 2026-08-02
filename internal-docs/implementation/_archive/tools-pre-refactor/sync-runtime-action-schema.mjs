#!/usr/bin/env node

// Byte-for-byte private mirror of the canonical runtime-action schema. The
// canonical architecture path remains the only schema owner.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  implementationRoot,
  readJson,
  repoRelative,
  repoRoot,
  sha256,
} from "./lib.mjs";

export const CANONICAL_SCHEMA_PATH = path.join(
  repoRoot,
  "docs/architecture/_meta/schemas/runtime-action-schema.json",
);
export const GENERATED_SCHEMA_PATH = path.join(
  implementationRoot,
  "generated/runtime-action-schema.json",
);
const POINTER_PATH = path.join(implementationRoot, "runtime-action-schema.json");

function fail(message) {
  throw new Error(message);
}

function validateOwnerPointer() {
  const pointer = readJson(POINTER_PATH);
  const canonical = repoRelative(CANONICAL_SCHEMA_PATH);
  const generated = path.relative(implementationRoot, GENERATED_SCHEMA_PATH).split(path.sep).join("/");
  if (pointer.schema_version !== "ioi.program.compatibility-pointer.v1") {
    fail(`${repoRelative(POINTER_PATH)} has an unknown pointer schema`);
  }
  if (pointer.owner !== canonical || pointer.generated_mirror !== generated) {
    fail(`${repoRelative(POINTER_PATH)} must name ${canonical} and ${generated}`);
  }
}

export function checkRuntimeActionSchemaMirror() {
  validateOwnerPointer();
  if (!fs.existsSync(GENERATED_SCHEMA_PATH)) {
    fail(`${repoRelative(GENERATED_SCHEMA_PATH)} is missing`);
  }
  const canonical = fs.readFileSync(CANONICAL_SCHEMA_PATH);
  const generated = fs.readFileSync(GENERATED_SCHEMA_PATH);
  if (!canonical.equals(generated)) {
    fail(
      `${repoRelative(GENERATED_SCHEMA_PATH)} is stale (canonical ${sha256(canonical)}, generated ${sha256(generated)})`,
    );
  }
  const parsed = JSON.parse(generated.toString("utf8"));
  if (parsed.schemaVersion !== "ioi.runtime-action-schema.v1") {
    fail(`${repoRelative(GENERATED_SCHEMA_PATH)} has an unknown schemaVersion`);
  }
  return { bytes: generated.length, sha256: sha256(generated) };
}

export function writeRuntimeActionSchemaMirror() {
  fs.mkdirSync(path.dirname(GENERATED_SCHEMA_PATH), { recursive: true });
  fs.copyFileSync(CANONICAL_SCHEMA_PATH, GENERATED_SCHEMA_PATH);
  return checkRuntimeActionSchemaMirror();
}

function parseMode(argv) {
  if (argv.length !== 1 || !["--write", "--check"].includes(argv[0])) {
    fail("choose exactly one of --write or --check");
  }
  return argv[0];
}

export function runRuntimeActionSchemaCli(argv) {
  const mode = parseMode(argv);
  const result = mode === "--write"
    ? writeRuntimeActionSchemaMirror()
    : checkRuntimeActionSchemaMirror();
  process.stdout.write(
    `runtime-action schema mirror ${mode === "--write" ? "written" : "checked"}: ${result.bytes} bytes, sha256 ${result.sha256}; canonical owner unchanged.\n`,
  );
}

const isMain = process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    runRuntimeActionSchemaCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`runtime-action schema sync failed: ${error.message}\n`);
    process.exit(1);
  }
}
