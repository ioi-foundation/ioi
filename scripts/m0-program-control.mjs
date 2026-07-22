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
  REVIEW_ANCHOR_FILE,
  REVIEW_FILE,
  attestProgramSourceReview,
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
      "Usage: node scripts/m0-program-control.mjs --init|--attest-review <review-anchor>|--write|--check",
      "",
      "  --init   Explicitly create missing unreviewed source worksheets; never overwrite.",
      `  --attest-review ${REVIEW_ANCHOR_FILE}`,
      "             Verify a supplied unsigned hash-chain snapshot and bind an unreviewed worksheet to it; never discovers a checkpoint, reads a private key, or signs.",
      "  --write  Validate reviewed sources and idempotently write deterministic artifacts.",
      "  --check  Read-only validation of discovery, supplied-snapshot matching, and artifact hashes; does not establish currentness.",
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

function attestReview(reviewAnchorPath) {
  if (reviewAnchorPath !== REVIEW_ANCHOR_FILE) {
    throw new Error(
      `--attest-review requires the tracked external evidence path ${REVIEW_ANCHOR_FILE}`,
    );
  }
  const discoveredEntries = discoverRepositorySurface(repoRoot);
  const { reviewAnchor, reviewLock, programSource } = loadM0Sources(repoRoot);
  const reviewed = attestProgramSourceReview(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
    reviewAnchor,
  );
  writeIfChanged(PROGRAM_SOURCE_FILE, stableStringify(reviewed));
  process.stdout.write(
    `Bound M0 program source to supplied snapshot epoch ${reviewed.review_attestation.review_epoch_id}; currentness not established.\n`,
  );
}

function writeArtifacts() {
  fs.mkdirSync(path.join(repoRoot, EVIDENCE_DIR), { recursive: true });
  const discoveredEntries = discoverRepositorySurface(repoRoot);
  const { reviewAnchor, reviewLock, programSource } = loadM0Sources(repoRoot);
  const built = buildM0Artifacts(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
    reviewAnchor,
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
    `M0 artifacts match supplied snapshot: ${discoveredEntries.length} entries, exit ${built.exitState}, ${writes} file(s) written; currentness not established.\n`,
  );
}

function checkArtifacts() {
  const checked = checkM0Artifacts(repoRoot);
  process.stdout.write(
    `M0 supplied-snapshot check passed: ${checked.discoveredEntries.length} entries, exit ${checked.exitState}, fingerprint ${checked.fingerprint}; currentness not established.\n`,
  );
}

function main(args) {
  const singleArgumentMode = args.length === 1
    && ["--init", "--write", "--check"].includes(args[0]);
  const attestMode = args.length === 2 && args[0] === "--attest-review";
  if (!singleArgumentMode && !attestMode) {
    usage();
    return 2;
  }
  if (args[0] === "--init") {
    initSources();
  } else if (args[0] === "--attest-review") {
    attestReview(args[1]);
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
