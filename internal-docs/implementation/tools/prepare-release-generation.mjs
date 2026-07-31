#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { ESTATE_ROOT, writeJsonDeterministic } from "./lib/estate.mjs";
import { buildReleaseGeneration } from "./lib/release-generation.mjs";

const index = process.argv.indexOf("--out");
const out = index >= 0 ? process.argv[index + 1] : null;
if (!out) {
  process.stderr.write("usage: prepare-release-generation.mjs --out <path outside canonical estate>\n");
  process.exit(2);
}
const target = path.resolve(out);
const canonical = fs.realpathSync(ESTATE_ROOT);
if (target === canonical || target.startsWith(`${canonical}${path.sep}`)) {
  process.stderr.write("REFUSED: release generation must be staged outside the canonical estate and promoted.\n");
  process.exit(1);
}
fs.mkdirSync(path.dirname(target), { recursive: true });
writeJsonDeterministic(target, buildReleaseGeneration());
process.stdout.write(`staged release generation at ${target}; not authoritative until promoted; no status or hold changed\n`);
