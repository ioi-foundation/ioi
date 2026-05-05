#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const args = process.argv.slice(2);
const pythonArgs = [
  "apps/autopilot/scripts/desktop_model_mounts_probe.py",
  ...args,
];

const result = spawnSync("python3", pythonArgs, {
  cwd: repoRoot,
  stdio: "inherit",
});

process.exit(result.status ?? 1);
