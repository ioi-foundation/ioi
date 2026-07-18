#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  atomicWriteFileSync,
} from "./lib/m0-program-control.mjs";
import {
  EVIDENCE_DIR,
  GENERATED_ARTIFACT_FILES,
  PROGRAM_SOURCE_FILE,
  REVIEW_FILE,
  buildM0Artifacts,
  checkM0Artifacts,
  createInitialProgramSource,
  createInitialReview,
  discoverRepositorySurface,
  loadM0Sources,
  stableStringify,
} from "./lib/m0-program-control-model.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptPath), "..");

function usage(stream = process.stderr) {
  stream.write(
    [
      "Usage: node scripts/m0-program-control.mjs --init|--write|--check",
      "",
      "  --init   Explicitly create missing unreviewed source worksheets; never overwrite.",
      "  --write  Validate reviewed sources and idempotently write deterministic artifacts.",
      "  --check  Read-only validation of discovery, sources, freshness, and artifact hashes.",
      "",
    ].join("\n"),
  );
}

function writeIfMissing(relativePath, source) {
  const absolutePath = path.join(repoRoot, relativePath);
  if (fs.existsSync(absolutePath)) {
    return false;
  }
  atomicWriteFileSync(absolutePath, source, { exclusive: true });
  return true;
}

function writeIfChanged(relativePath, source) {
  const absolutePath = path.join(repoRoot, relativePath);
  let current = null;
  try {
    current = fs.readFileSync(absolutePath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  if (current === source) {
    return false;
  }
  atomicWriteFileSync(absolutePath, source);
  return true;
}

function initSources() {
  fs.mkdirSync(path.join(repoRoot, EVIDENCE_DIR), { recursive: true });
  const discoveredEntries = discoverRepositorySurface(repoRoot);
  const initialized = [];
  if (writeIfMissing(
    REVIEW_FILE,
    stableStringify(createInitialReview(repoRoot, discoveredEntries)),
  )) {
    initialized.push(REVIEW_FILE);
  }
  if (writeIfMissing(
    PROGRAM_SOURCE_FILE,
    stableStringify(createInitialProgramSource(repoRoot)),
  )) {
    initialized.push(PROGRAM_SOURCE_FILE);
  }
  process.stdout.write(
    initialized.length > 0
      ? `Initialized ${initialized.length} M0 source file(s); review lock remains fail-closed.\n`
      : "M0 source files already exist; nothing written.\n",
  );
}

function writeArtifacts() {
  fs.mkdirSync(path.join(repoRoot, EVIDENCE_DIR), { recursive: true });
  const discoveredEntries = discoverRepositorySurface(repoRoot);
  const { reviewLock, programSource } = loadM0Sources(repoRoot);
  const built = buildM0Artifacts(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
  );
  let writes = 0;
  for (const name of GENERATED_ARTIFACT_FILES) {
    if (writeIfChanged(
      `${EVIDENCE_DIR}/${name}`,
      built.rendered.get(name),
    )) {
      writes += 1;
    }
  }
  process.stdout.write(
    `M0 artifacts current: ${discoveredEntries.length} entries, exit ${built.exitState}, ${writes} file(s) written.\n`,
  );
}

function checkArtifacts() {
  const checked = checkM0Artifacts(repoRoot);
  process.stdout.write(
    `M0 check passed: ${checked.discoveredEntries.length} entries, exit ${checked.exitState}, fingerprint ${checked.fingerprint}.\n`,
  );
}

function main(args) {
  if (args.length !== 1 || !["--init", "--write", "--check"].includes(args[0])) {
    usage();
    return 2;
  }
  if (args[0] === "--init") {
    initSources();
  } else if (args[0] === "--write") {
    writeArtifacts();
  } else {
    checkArtifacts();
  }
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
}
