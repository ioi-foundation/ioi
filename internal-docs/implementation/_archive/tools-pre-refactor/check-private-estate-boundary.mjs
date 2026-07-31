#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { failWith, implementationRoot, readJson, repoRoot, sha256File } from "./lib.mjs";

function worktreePaths(porcelain) {
  return porcelain
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => line.slice(3))
    .filter((entry) => !entry.startsWith("internal-docs/implementation/"))
    .sort();
}

if (process.argv[2] === "--self-test-status-parser") {
  const actual = worktreePaths([
    "M  staged.md",
    " M unstaged.md",
    "MM both.md",
    "?? untracked.md",
    "!! internal-docs/implementation/ignored.md",
  ].join("\n"));
  const expected = ["both.md", "staged.md", "unstaged.md", "untracked.md"];
  failWith("private-estate-boundary status-parser self-test", JSON.stringify(actual) === JSON.stringify(expected)
    ? []
    : [`expected ${expected.join(", ")}; found ${actual.join(", ")}`]);
  process.stdout.write("private-estate-boundary status-parser self-test passed: staged, unstaged, and untracked paths are visible while the ignored private estate is excluded\n");
  process.exit(0);
}
if (process.argv.length !== 2) {
  failWith("private-estate-boundary check", ["usage: check-private-estate-boundary.mjs [--self-test-status-parser]"]);
}

const errors = [];
const tracked = spawnSync("git", ["ls-files", "internal-docs/implementation"], { cwd: repoRoot, encoding: "utf8" });
if (tracked.status !== 0) errors.push(`git ls-files failed: ${tracked.stderr.trim()}`);
if (tracked.stdout.trim()) errors.push(`private implementation files became tracked: ${tracked.stdout.trim().split(/\r?\n/u).join(", ")}`);

const checkIgnore = spawnSync("git", ["check-ignore", "-q", "internal-docs/implementation/README.md"], { cwd: repoRoot });
if (checkIgnore.status !== 0) errors.push("internal-docs/implementation is not ignored");

const baselinePath = path.join(implementationRoot, "audits/reconciliation/pre-existing-tracked-changes.v1.json");
if (!fs.existsSync(baselinePath)) {
  errors.push("pre-existing tracked-change baseline is missing");
} else {
  const baseline = readJson(baselinePath);
  const status = spawnSync("git", ["status", "--porcelain"], { cwd: repoRoot, encoding: "utf8" });
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" });
  const branch = spawnSync("git", ["branch", "--show-current"], { cwd: repoRoot, encoding: "utf8" });
  if (status.status !== 0 || head.status !== 0 || branch.status !== 0) {
    errors.push(`cannot resolve tracked checkout identity: ${status.stderr || head.stderr || branch.stderr}`);
  }
  const actual = worktreePaths(status.stdout);
  const expected = baseline.paths.map((entry) => entry.path).sort();
  const currentCommit = head.stdout.trim();
  const currentBranch = branch.stdout.trim();
  const isFrozenDirtyBaseline = JSON.stringify(actual) === JSON.stringify(expected)
    && currentCommit === baseline.commit
    && currentBranch === baseline.branch;
  const resolution = baseline.resolved_authoritative_checkout;
  const isReviewedCleanResolution = actual.length === 0
    && resolution
    && currentCommit === resolution.commit
    && (!currentBranch || currentBranch === resolution.branch);
  if (!isFrozenDirtyBaseline && !isReviewedCleanResolution) {
    errors.push(`tracked checkout is neither frozen dirty baseline ${baseline.branch}@${baseline.commit} nor its reviewed clean authoritative resolution; found ${currentBranch || "detached"}@${currentCommit} with ${actual.join(", ") || "no dirty paths"}`);
  }
  for (const entry of baseline.paths) {
    const absolute = path.join(repoRoot, entry.path);
    if (!fs.existsSync(absolute) || sha256File(absolute) !== entry.working_tree_sha256) errors.push(`pre-existing tracked change was modified: ${entry.path}`);
  }
}

const forbiddenTracked = spawnSync("git", ["grep", "-l", "ioi.program.work_item.v1", "--", "docs/architecture", ":(exclude)docs/architecture/_archive"], { cwd: repoRoot, encoding: "utf8" });
if (forbiddenTracked.status === 0 && forbiddenTracked.stdout.trim()) errors.push(`tracked canon contains private work-item records: ${forbiddenTracked.stdout.trim()}`);

failWith("private-estate-boundary check", errors);
process.stdout.write("private-estate-boundary check passed: private files remain ignored and the seven pre-existing tracked bytes are exact in the frozen dirty baseline or reviewed clean authoritative resolution\n");
