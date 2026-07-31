#!/usr/bin/env node

// Read-only umbrella freshness check for private projections. Each projection
// remains owned by its dedicated deterministic generator/check pair.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { implementationRoot, repoRelative, repoRoot } from "./lib.mjs";

const checks = [
  {
    label: "program state",
    command: "check-program-state.mjs",
    args: [],
  },
  {
    label: "architecture coverage",
    command: "tools/generate-architecture-coverage.mjs",
    args: ["--check"],
  },
  {
    label: "Hypervisor surface coverage",
    command: "tools/generate-hypervisor-surface-coverage.mjs",
    args: ["--check"],
  },
  {
    label: "runtime-action schema mirror",
    command: "tools/sync-runtime-action-schema.mjs",
    args: ["--check"],
  },
  {
    label: "runtime-kernel residual",
    command: "tools/generate-runtime-kernel-residual.mjs",
    args: ["--check"],
  },
];

const generatorDeclarations = [
  {
    label: "program state",
    file: "program-state.json",
    generator: "internal-docs/implementation/tools/generate-program-state.mjs",
  },
  {
    label: "architecture coverage",
    file: "generated/architecture-coverage.v1.json",
    generator: "internal-docs/implementation/tools/generate-architecture-coverage.mjs",
  },
  {
    label: "Hypervisor surface coverage",
    file: "generated/hypervisor-surface-coverage.v1.json",
    generator: "internal-docs/implementation/tools/generate-hypervisor-surface-coverage.mjs",
  },
  {
    label: "runtime-kernel residual",
    file: "generated/runtime-kernel-namespace-residual.v1.json",
    generator: "internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs",
  },
];

const errors = [];
const notices = [];
for (const check of checks) {
  const file = path.join(implementationRoot, check.command);
  if (!fs.existsSync(file)) {
    errors.push(`${check.label}: missing dedicated checker ${repoRelative(file)}`);
    continue;
  }
  const result = spawnSync(process.execPath, [file, ...check.args], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    errors.push(
      `${check.label}: ${(result.stderr || result.stdout || "checker returned no output").trim()}`,
    );
    continue;
  }
  notices.push(`${check.label}: ${(result.stdout || "PASS").trim()}`);
}

for (const declaration of generatorDeclarations) {
  const file = path.join(implementationRoot, declaration.file);
  if (!fs.existsSync(file)) {
    errors.push(`${declaration.label}: missing projection ${repoRelative(file)}`);
    continue;
  }
  let projection;
  try {
    projection = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    errors.push(`${declaration.label}: invalid JSON in ${repoRelative(file)}: ${error.message}`);
    continue;
  }
  const generatorPath = typeof projection.generator === "string"
    ? projection.generator
    : projection.generator?.path;
  if (generatorPath !== declaration.generator) {
    errors.push(
      `${declaration.label}: generator declaration is ${generatorPath ?? "missing"}; expected ${declaration.generator}`,
    );
  }
  if (
    typeof projection.generator !== "object"
    || typeof projection.generator?.write_command !== "string"
    || typeof projection.generator?.check_command !== "string"
  ) {
    errors.push(`${declaration.label}: generator must declare write_command and check_command`);
  }
}

if (errors.length > 0) {
  process.stderr.write(
    `generated-projection check failed with ${errors.length} error(s):\n${errors.map((error) => `- ${error}`).join("\n")}\n`,
  );
  process.exit(1);
}

for (const notice of notices) process.stdout.write(`${notice}\n`);
process.stdout.write(
  `generated-projection check passed: ${checks.length} dedicated projections are byte-current. No status changed and no stage was closed.\n`,
);
