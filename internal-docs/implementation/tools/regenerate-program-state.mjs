#!/usr/bin/env node
// One command for the program-state regeneration order.
//
// WHY THIS EXISTS. The order is `generate-now --write` → `m0 --write` →
// `m0 --check`, and it is NOT arbitrary: M0 discovers the artifacts
// generate-now writes, so regenerating them afterwards invalidates the M0
// artifacts that were just produced. That constraint appeared when NOW.md and
// program-state.v1.json became tracked, it lived nowhere but a commit message,
// and it was violated the very next round — the detached run caught a commit
// that shipped stale M0 artifacts while `m0 --write` had reported success.
// An order that lives only in prose loses.
//
// THE STAGING HAZARD, handled explicitly. M0 discovery reads the GIT INDEX. If
// a tracked path has been deleted on disk but the deletion is not staged —
// exactly the state left by `transition.mjs` moving a record between status
// directories — discovery `lstat`s a path git still tracks and throws ENOENT
// from inside itself. That reads as a tool crash and is a staging state.
//
// A wrapper that can be crashed by an intermediate staging state is not a
// wrapper. This one REFUSES BY NAME before running anything, rather than
// staging on the caller's behalf: staging is a decision about what enters a
// commit, and a regeneration tool has no business making it silently.

import { execFileSync, execSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");

const STEPS = Object.freeze([
  { name: "generate-now --write", argv: ["internal-docs/implementation/tools/generate-now.mjs", "--write"] },
  { name: "m0 --write", argv: ["scripts/m0-program-control.mjs", "--write"] },
  { name: "m0 --check", argv: ["scripts/m0-program-control.mjs", "--check"] },
]);

/// Tracked paths deleted on disk whose deletion is NOT staged.
///
/// `git status --porcelain` reports index and worktree status in columns one
/// and two. ` D` is the hazard: unmodified in the index, deleted in the
/// worktree — git still tracks it, the filesystem does not have it, and M0
/// discovery will lstat it.
export function unstagedDeletions(porcelain) {
  return porcelain
    .split("\n")
    .filter((line) => line.length > 3)
    .filter((line) => line[0] === " " && line[1] === "D")
    .map((line) => line.slice(3).trim());
}

function main() {
  const porcelain = execSync("git status --porcelain", { cwd: REPO }).toString();
  const hazards = unstagedDeletions(porcelain);
  if (hazards.length > 0) {
    console.log(
      `[ERROR] regenerate-program-state: PRECONDITION unstaged-tracked-deletion — ` +
        `${hazards.length} tracked path(s) deleted on disk with the deletion unstaged. ` +
        `M0 discovery reads the git index, so it would lstat a path git still tracks and throw ` +
        `ENOENT from inside discovery — a crash that is really a staging state. ` +
        `Stage the deletions (git add -A) and re-run; this tool will not stage on your behalf, ` +
        `because staging decides what enters a commit.`,
    );
    for (const path of hazards.slice(0, 5)) console.log(`  unstaged deletion: ${path}`);
    console.log("regenerate-program-state: FAIL (1 error, 0 warn, 0 skip)");
    process.exit(1);
  }

  for (const step of STEPS) {
    try {
      execFileSync(process.execPath, step.argv, { cwd: REPO, stdio: "inherit" });
    } catch {
      console.log(
        `[ERROR] regenerate-program-state: step "${step.name}" failed; the order is ` +
          `generate-now --write -> m0 --write -> m0 --check and a later step cannot ` +
          `repair an earlier one`,
      );
      console.log("regenerate-program-state: FAIL (1 error, 0 warn, 0 skip)");
      process.exit(1);
    }
  }
  console.log(
    `regenerate-program-state: PASS (0 error, 0 warn, 0 skip) — ${STEPS.length} steps in order`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
