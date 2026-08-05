#!/usr/bin/env node
// Integration regression for the packet-convention ratchet: a REAL git
// repository, REAL commits, the PRODUCTION gate run against them.
//
// WHY IT CANNOT BE A UNIT TEST. The hole was never in the predicate — set
// subtraction was correct. It was in WHICH HISTORY the caller consulted:
// `git show HEAD:` returns the commit under evaluation, so a commit that both
// added a directory to the baseline and committed it proved the addition legal
// by pointing at itself. Faking the git ops would have faked away the entire
// bug. Only real commits exercise which revision is read.
//
// This is self-attestation, the fourth appearance of the class in this program,
// and Codex handed over the red subject. It is kept, not paraphrased.

import { execSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const BASELINE = "scripts/packet-convention-baseline.v1.json";
const GATE = "internal-docs/implementation/tools/check-claims-coverage.mjs";

const git = (cwd, args) =>
  execSync(`git ${args}`, { cwd, stdio: ["ignore", "pipe", "pipe"] }).toString();

/// Build a throwaway repository whose HEAD both ADDS a baseline entry and
/// commits it — the shape that a HEAD-reading check declares legal.
function buildAttackRepo() {
  const dir = mkdtempSync(join(tmpdir(), "ioi-ratchet-attack-"));
  git(dir, "init -q");
  git(dir, 'config user.email "test@local"');
  git(dir, 'config user.name "test"');

  mkdirSync(join(dir, "scripts"), { recursive: true });
  mkdirSync(join(dir, "internal-docs/implementation/tools"), { recursive: true });
  mkdirSync(join(dir, "internal-docs/implementation/claims-coverage"), { recursive: true });
  mkdirSync(join(dir, "docs/evidence/pre-existing-cut"), { recursive: true });
  cpSync(join(REPO, "scripts"), join(dir, "scripts"), { recursive: true });
  cpSync(join(REPO, "internal-docs/implementation/tools"), join(dir, "internal-docs/implementation/tools"), { recursive: true });
  symlinkSync(join(REPO, "node_modules"), join(dir, "node_modules"));

  const writeBaseline = (dirs) =>
    writeFileSync(join(dir, BASELINE), `${JSON.stringify({
      evidence_format: "ioi.checks.packet_convention_baseline.v1",
      directories: dirs,
    }, null, 2)}\n`);

  // Commit 1: an honest baseline holding one pre-convention directory.
  writeBaseline(["pre-existing-cut"]);
  writeFileSync(join(dir, "docs/evidence/pre-existing-cut/some.log"), "x\n");
  git(dir, "add -A");
  git(dir, 'commit -q -m "honest baseline"');

  // Commit 2: THE ATTACK. A NEW evidence directory with no PACKET.md appears,
  // and the same commit writes it into the baseline. Nothing is internally
  // inconsistent — the only evidence is that this entry has no history.
  mkdirSync(join(dir, "docs/evidence/smuggled-cut"), { recursive: true });
  writeFileSync(join(dir, "docs/evidence/smuggled-cut/some.log"), "x\n");
  writeBaseline(["pre-existing-cut", "smuggled-cut"]);
  git(dir, "add -A");
  git(dir, 'commit -q -m "add a directory and exempt it in the same commit"');
  return dir;
}

function main() {
  const dir = buildAttackRepo();
  let output = "";
  let exitCode = 0;
  try {
    output = execSync(`node ${GATE}`, { cwd: dir }).toString();
  } catch (error) {
    output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    exitCode = error.status ?? 1;
  }

  const refused = exitCode !== 0 && /baseline ADDS smuggled-cut/.test(output);
  console.log(
    `test-packet-convention-ratchet-integration: ${refused ? "PASS" : "FAIL"} — a commit that adds an ` +
    `evidence directory AND exempts it in the same commit must be REFUSED; got exit ${exitCode}`,
  );
  rmSync(dir, { recursive: true, force: true });
  process.exit(refused ? 0 : 1);
}

main();
