#!/usr/bin/env node
// Integration regression for check-attestation-chain: a REAL git repository,
// REAL commits, the PRODUCTION gate file run against them.
//
// WHY IT CANNOT BE A UNIT TEST. The injected-git-ops pattern that serves
// check-claims-coverage cannot reach this defect. The hole was never in the
// predicate — `evaluateAppendOnly` was correct — it was in WHICH HISTORY the
// caller consulted: `git rev-list … HEAD` includes the commit under
// evaluation, so a commit containing novel rewritten bytes proved those bytes
// "were held before" by pointing at itself. Faking the git ops would have
// faked away the entire bug. Only real commits exercise which revisions are
// searched.
//
// This is the invisible-evidence class at the git layer: the candidate
// vouching for itself.

import { execSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const ANCHOR = "docs/evidence/m0-program-control/review-epoch-anchor.json";
const SIDECAR = "docs/evidence/m5-event-substrate/review-epoch-2-split.v1.json";

function git(cwd, args) {
  return execSync(`git ${args}`, { cwd, stdio: ["ignore", "pipe", "pipe"] }).toString();
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

/// Build a throwaway repository whose HEAD contains a head-entry REWRITE plus
/// a matching head digest and a rebound sidecar — Codex's exact attack shape.
/// Every artifact is internally consistent; only the history betrays it.
async function buildAttackRepo() {
  const dir = mkdtempSync(join(tmpdir(), "ioi-attest-attack-"));
  git(dir, "init -q");
  git(dir, 'config user.email "test@local"');
  git(dir, 'config user.name "test"');

  // The production gate and the model function it imports, copied verbatim.
  mkdirSync(join(dir, "scripts", "lib"), { recursive: true });
  mkdirSync(join(dir, dirname(ANCHOR)), { recursive: true });
  mkdirSync(join(dir, dirname(SIDECAR)), { recursive: true });
  // Copy the whole scripts tree: the model module has transitive siblings, and
  // a trimmed stand-in would be a reimplementation rather than the production
  // gate. What is under test must be the shipped file.
  cpSync(join(REPO, "scripts"), join(dir, "scripts"), { recursive: true });
  // The model module imports from node_modules; symlink rather than copy so the
  // throwaway repo resolves the same dependencies the real gate resolves.
  symlinkSync(join(REPO, "node_modules"), join(dir, "node_modules"));

  const { reviewAnchorEntrySha256 } = await import(join(REPO, "scripts", "lib", "m0-program-control-model.mjs"));
  const entry = (sequence, marker) => ({
    sequence,
    epoch_id: `epoch-${sequence}`,
    reviewed_as_of: "2026-01-01",
    marker,
  });

  // Commit 1: an honest two-entry chain with a sidecar bound to the head.
  const honest = [entry(1, "one"), entry(2, "two")];
  const write = (epochs) => {
    const head = epochs[epochs.length - 1];
    writeFileSync(join(dir, ANCHOR), `${JSON.stringify({
      epochs,
      head: { entry_sha256: reviewAnchorEntrySha256(head), epoch_id: head.epoch_id, sequence: head.sequence },
    }, null, 2)}\n`);
    writeFileSync(join(dir, SIDECAR), `${JSON.stringify({
      evidence_format: "ioi.m0.review_epoch_split.v1",
      epoch_id: head.epoch_id, sequence: head.sequence,
      bound_entry_sha256: reviewAnchorEntrySha256(head),
    }, null, 2)}\n`);
  };
  write(honest);
  git(dir, "add -A");
  git(dir, 'commit -q -m "honest chain"');

  // Commit 2: THE ATTACK. Entry 2 is rewritten to bytes never held anywhere,
  // the head digest is updated to match, and the sidecar is rebound. Nothing
  // is internally inconsistent — the only evidence is that these bytes have no
  // history.
  write([entry(1, "one"), entry(2, "REWRITTEN-NOVEL")]);
  git(dir, "add -A");
  git(dir, 'commit -q -m "synthetic head rewrite with updated digest and rebound sidecar"');
  return dir;
}

async function main() {
  const dir = await buildAttackRepo();
  let output = "";
  let exitCode = 0;
  try {
    output = execSync("node scripts/check-attestation-chain.mjs", { cwd: dir }).toString();
  } catch (error) {
    output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    exitCode = error.status ?? 1;
  }

  const refused = exitCode !== 0 && /REWRITTEN in place/.test(output);
  console.log(output.trim().split("\n").slice(-2).join("\n"));
  console.log(
    `test-attestation-chain-integration: ${refused ? "PASS" : "FAIL"} — a committed head rewrite with a matching head digest and rebound sidecar must be REFUSED; got exit ${exitCode}`,
  );
  rmSync(dir, { recursive: true, force: true });
  process.exit(refused ? 0 : 1);
}

main();
