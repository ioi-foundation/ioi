#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const implementationRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const repoRoot = path.resolve(implementationRoot, "../..");

export function toPosix(value) {
  return value.split(path.sep).join("/");
}

export function implementationRelative(absolutePath) {
  return toPosix(path.relative(implementationRoot, absolutePath));
}

export function repoRelative(absolutePath) {
  return toPosix(path.relative(repoRoot, absolutePath));
}

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function sha256File(file) {
  return sha256(fs.readFileSync(file));
}

export function listTreeFiles(root, { includeSymlinks = true } = {}) {
  const output = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile() || (includeSymlinks && entry.isSymbolicLink())) {
        output.push(absolute);
      }
    }
  };
  visit(root);
  return output.sort((left, right) => left.localeCompare(right));
}

export function writeDeterministic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, stableJson(value));
}

export function checkDeterministic(file, value) {
  const expected = stableJson(value);
  if (!fs.existsSync(file)) {
    return { ok: false, reason: `${repoRelative(file)} is missing` };
  }
  const actual = fs.readFileSync(file, "utf8");
  if (actual !== expected) {
    return {
      ok: false,
      reason: `${repoRelative(file)} is stale (expected ${sha256(expected)}, found ${sha256(actual)})`,
    };
  }
  return { ok: true };
}

export function git(args, options = {}) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    ...options,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

export function markdownAnchor(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

export function failWith(prefix, errors) {
  if (errors.length === 0) return;
  process.stderr.write(
    `${prefix} failed with ${errors.length} error(s):\n${errors
      .map((error) => `- ${error}`)
      .join("\n")}\n`,
  );
  process.exit(1);
}

export const STATUS_VALUES = new Set([
  "proposed",
  "scoped",
  "active",
  "evidence_ready",
  "verified",
  "blocked",
  "superseded",
  "rejected",
]);
