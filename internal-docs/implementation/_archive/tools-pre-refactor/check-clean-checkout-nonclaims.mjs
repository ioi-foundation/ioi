#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  implementationRoot,
  readJson,
  repoRoot,
  sha256File,
} from "./lib.mjs";

const baseline = readJson(path.join(implementationRoot, "audits/reconciliation/pre-existing-tracked-changes.v1.json"));
const git = (args) => spawnSync("git", args, { cwd: repoRoot, encoding: "utf8" });
const head = git(["rev-parse", "HEAD"]);
const branch = git(["branch", "--show-current"]);
if (head.status !== 0 || branch.status !== 0) {
  process.stderr.write(`clean-checkout check failed: ${head.stderr || branch.stderr}\n`);
  process.exit(1);
}
const currentCommit = head.stdout.trim();
const currentBranch = branch.stdout.trim();
const status = spawnSync("git", ["status", "--porcelain"], { cwd: repoRoot, encoding: "utf8" });
if (status.status !== 0) {
  process.stderr.write(`clean-checkout check failed: ${status.stderr}\n`);
  process.exit(1);
}
const dirty = status.stdout.split(/\r?\n/u).filter(Boolean).map((line) => line.slice(3)).filter((entry) => !entry.startsWith("internal-docs/implementation/"));
const expected = baseline.paths.map((entry) => entry.path).sort();
if (dirty.length === 0) {
  const resolution = baseline.resolved_authoritative_checkout;
  const errors = [];
  if (!resolution || typeof resolution !== "object") {
    errors.push("no reviewed authoritative resolution commit is recorded for the seven pre-existing tracked bytes");
  } else {
    if (!/^[a-f0-9]{40}$/u.test(resolution.commit ?? "")) errors.push("resolved authoritative commit is malformed");
    if (currentCommit !== resolution.commit) errors.push(`HEAD ${currentCommit} is not the reviewed authoritative resolution ${resolution.commit}`);
    if (currentBranch && currentBranch !== resolution.branch) errors.push(`branch ${currentBranch} is not the reviewed authoritative branch ${resolution.branch}`);
    for (const entry of baseline.paths) {
      const absolute = path.join(repoRoot, entry.path);
      if (!fs.existsSync(absolute) || sha256File(absolute) !== entry.working_tree_sha256) {
        errors.push(`committed authoritative bytes do not match the preserved pre-existing bytes: ${entry.path}`);
      }
    }
  }
  if (errors.length > 0) {
    process.stderr.write(`clean-checkout check failed: ${errors.join("; ")}\n`);
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({
    result: "PASS",
    check: "clean-authoritative-checkout",
    branch: resolution.branch,
    commit: resolution.commit,
    committed_tracked_bytes_verified: expected,
  }) + "\n");
  process.exit(0);
}
if (JSON.stringify([...dirty].sort()) === JSON.stringify(expected)) {
  if (currentCommit !== baseline.commit || currentBranch !== baseline.branch) {
    process.stderr.write(`clean-checkout check failed: recognized dirty bytes are attached to ${currentBranch || "detached"}@${currentCommit}, not frozen baseline ${baseline.branch}@${baseline.commit}\n`);
    process.exit(1);
  }
  for (const entry of baseline.paths) {
    const absolute = path.join(repoRoot, entry.path);
    if (!fs.existsSync(absolute) || sha256File(absolute) !== entry.working_tree_sha256) {
      process.stderr.write(`clean-checkout check failed: pre-existing tracked bytes changed: ${entry.path}\n`);
      process.exit(1);
    }
  }
  process.stdout.write(JSON.stringify({
    result: "SKIP",
    check: "clean-authoritative-checkout",
    reason: "recognized pre-existing dirty checkout",
    dirty_paths: expected,
    nonclaims: [
      "This private transaction did not modify the pre-existing tracked paths.",
      "A clean-checkout proof was not obtained.",
      "SKIP is not a stage, work-item, runtime, or release success claim."
    ]
  }) + "\n");
  process.exit(0);
}
process.stderr.write(`clean-checkout check failed: unexpected tracked dirty paths ${dirty.join(", ")}\n`);
process.exit(1);
