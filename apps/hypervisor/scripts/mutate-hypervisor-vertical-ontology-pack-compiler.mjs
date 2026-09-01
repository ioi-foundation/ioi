#!/usr/bin/env node
// M05.10 planted mutation battery. Every mutant changes a real daemon admission branch, rebuilds
// that daemon, and must redden one named live-verifier assertion. Sources are restored byte-for-byte
// after every row and the pristine daemon is rebuilt before exit.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const TARGET = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");
const SOURCES = Object.freeze({
  pack: path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/vertical_ontology_pack_routes.rs"),
  binding: path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/vertical_pack_worker_binding_routes.rs"),
});

const MUTANTS = Object.freeze([
  {
    id: "jurisdiction-absence-is-accepted",
    source: "binding",
    target: "a pack with no jurisdiction fails closed at compilation",
    from: "    if jurisdiction_refs.is_empty() {",
    to: "    if false && jurisdiction_refs.is_empty() {",
  },
  {
    id: "required-field-absence-is-not-escalated",
    source: "binding",
    target: "field coverage is total and a required field with no admissible proposal escalates without producing a value",
    from: '                cause: "required_field_proposal_absent",',
    to: '                cause: "field_proposal_absent",',
  },
  {
    id: "caller-authored-compiled-fields-are-admitted",
    source: "binding",
    target: "caller-authored compiled arrays are refused before any owner seam is crossed",
    from: '    "compiled_field_contracts",\n    "compiled_evidence_requirements",',
    to: '    "compiled_evidence_requirements",',
  },
  {
    id: "binding-authority-nonclaim-is-overstated",
    source: "binding",
    target: "WorkerComposition remains an explicit M14-owned unresolved nonclaim and compilation grants no authority",
    from: '        "authority_nonclaim": "vertical_pack_worker_binding_grants_no_authority",',
    to: '        "authority_nonclaim": "vertical_pack_worker_binding_grants_authority",',
  },
  {
    id: "pack-authority-nonclaim-is-overstated",
    source: "pack",
    target: "the pack records the semantic, authority, legality and correctness boundaries",
    from: '        "authority_nonclaim": "vertical_ontology_pack_grants_no_authority",',
    to: '        "authority_nonclaim": "vertical_ontology_pack_grants_authority",',
  },
]);

const anchorsOnly = process.argv.includes("--anchors");
const originals = new Map(Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]));
let restoring = false;

function occurrenceCount(text, needle) {
  return text.split(needle).length - 1;
}

function restore() {
  if (restoring) return;
  restoring = true;
  try {
    for (const [key, text] of originals) fs.writeFileSync(SOURCES[key], text);
  } finally {
    restoring = false;
  }
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    restore();
    process.exit(128);
  });
}
process.on("exit", restore);

for (const mutant of MUTANTS) {
  const count = occurrenceCount(originals.get(mutant.source), mutant.from);
  if (count !== 1) {
    process.stderr.write(`ANCHOR ERROR ${mutant.id}: expected exactly one source anchor, found ${count}\n`);
    process.exit(1);
  }
}
if (anchorsOnly) {
  process.stdout.write(`vertical-ontology-pack-compiler mutation anchors: ${MUTANTS.length}/${MUTANTS.length}\n`);
  process.exit(0);
}

function build() {
  return spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT,
    env: { ...process.env, CARGO_TARGET_DIR: TARGET },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m0510-mutations-"));
const rows = [];
try {
  for (const mutant of MUTANTS) {
    restore();
    const original = originals.get(mutant.source);
    fs.writeFileSync(SOURCES[mutant.source], original.replace(mutant.from, mutant.to));
    const compiled = build();
    if (compiled.status !== 0) {
      rows.push({ id: mutant.id, result: "DID_NOT_BUILD", detail: (compiled.stderr || compiled.stdout || "").slice(-500) });
      process.stdout.write(`MISS  ${mutant.id} — mutant did not build\n`);
      continue;
    }
    const child = spawnSync(process.execPath, [path.join(HERE, "verify-hypervisor-vertical-ontology-pack-compiler.mjs")], {
      cwd: ROOT,
      env: {
        ...process.env,
        CARGO_TARGET_DIR: TARGET,
        IOI_M0510_DAEMON_PREBUILT: "1",
        IOI_VERIFIER_CENSUS_DIR: "",
      },
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    fs.writeFileSync(path.join(scratch, `${mutant.id}.log`), output);
    const targeted = child.status !== 0 && output.includes(`FAIL  ${mutant.target}`);
    rows.push({ id: mutant.id, result: targeted ? "RED_ON_TARGET" : child.status !== 0 ? "RED_OFF_TARGET" : "SURVIVED" });
    process.stdout.write(`${targeted ? "RED " : "MISS"}  ${mutant.id} — ${targeted ? "target assertion failed" : `status ${child.status}`}\n`);
  }
} finally {
  restore();
  const pristine = build();
  if (pristine.status !== 0) {
    process.stderr.write(`pristine daemon rebuild failed after restore:\n${(pristine.stderr || pristine.stdout || "").slice(-4000)}\n`);
    process.exit(1);
  }
  fs.rmSync(scratch, { recursive: true, force: true });
}

const killed = rows.filter((row) => row.result === "RED_ON_TARGET").length;
process.stdout.write(`\nvertical-ontology-pack-compiler mutation battery: ${killed}/${MUTANTS.length} RED ON TARGET\n`);
process.exit(killed === MUTANTS.length ? 0 : 1);
