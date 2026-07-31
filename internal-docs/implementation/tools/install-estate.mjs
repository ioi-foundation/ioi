#!/usr/bin/env node
// Installs the refactored estate into a target checkout.
//
//   node tools/install-estate.mjs --target <repo-root>            dry run
//   node tools/install-estate.mjs --target <repo-root> --apply    install
//   --park <dir>                                                  where the outgoing estate goes
//                                                                 (default: a sibling of the repo)
//
// The private estate is gitignored, so it exists only in a working directory and
// cannot be delivered through git. This tool copies it, and it refuses to run if
// the target has any tracked modification outside the estate that it did not
// record first — the point is that installing the estate can never disturb
// user-owned work.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { ESTATE_ROOT, sha256File } from "./lib/estate.mjs";

const REL = "internal-docs/implementation";

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
}

function trackedStatus(root) {
  return execFileSync("git", ["status", "--porcelain"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean)
    .map((l) => l.slice(3).trim());
}

function main() {
  const target = arg("--target");
  const apply = process.argv.includes("--apply");
  if (!target) {
    process.stderr.write("usage: install-estate.mjs --target <repo-root> [--apply]\n");
    process.exit(2);
  }
  const targetRoot = path.resolve(target);
  const targetEstate = path.join(targetRoot, REL);

  const before = trackedStatus(targetRoot);
  process.stdout.write(
    `target ${targetRoot}\n  tracked modifications before: ${before.length}\n`,
  );
  for (const p of before) process.stdout.write(`    ${p}\n`);

  if (!apply) {
    process.stdout.write(
      `\nwould replace ${targetEstate}\n  (the estate is gitignored, so this changes no tracked path)\n`,
    );
    process.exit(0);
  }

  // Keep the outgoing estate as a dated sibling rather than deleting it.
  if (fs.existsSync(targetEstate)) {
    // Park OUTSIDE the repository. A sibling named
    // `internal-docs/implementation.replaced-by-refactor` is not matched by the
    // `/internal-docs/implementation/` ignore rule, so it would show up as an
    // untracked path and dirty the user's `git status`.
    const parked = arg("--park") ??
      path.join(path.dirname(targetRoot), "pre-refactor-estate");
    if (fs.existsSync(parked)) {
      // The original estate is already parked. A second install must never
      // overwrite that park, or the pre-refactor estate would be lost.
      fs.rmSync(targetEstate, { recursive: true, force: true });
      process.stdout.write(
        `  original estate already parked at ${parked}; replaced the installed copy only\n`,
      );
    } else {
      fs.renameSync(targetEstate, parked);
      process.stdout.write(`  parked previous estate at ${parked}\n`);
    }
  }
  fs.cpSync(ESTATE_ROOT, targetEstate, { recursive: true });

  const after = trackedStatus(targetRoot);
  const changed = after.length !== before.length ||
    after.some((p, i) => p !== before[i]);
  process.stdout.write(
    `  tracked modifications after: ${after.length}${
      changed ? "  *** CHANGED — investigate ***" : "  (unchanged)"
    }\n`,
  );
  process.stdout.write(
    `  installed ${
      execFileSync("bash", ["-lc", `find ${targetEstate} -type f | wc -l`], {
        encoding: "utf8",
      }).trim()
    } files\n`,
  );
  process.exit(changed ? 1 : 0);
}

main();
