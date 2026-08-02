#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { failWith, implementationRoot, listTreeFiles, repoRoot } from "./lib.mjs";

const roots = ["stage-guides", "proof-gates"].map((relative) => path.join(implementationRoot, relative));
const files = roots.flatMap((root) => fs.existsSync(root) ? listTreeFiles(root).filter((file) => file.endsWith(".md")) : []);
const errors = [];
const required = ["document_class", "sequencer", "stage_ids", "work_packages", "canon_owners", "owns", "does_not_own", "regeneration"];

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const header = /^---\n([\s\S]*?)\n---\n/u.exec(source)?.[1];
  if (!header) {
    errors.push(`${path.relative(implementationRoot, file)} lacks a front-matter header`);
    continue;
  }
  for (const key of required) {
    if (!new RegExp(`^${key}:`, "mu").test(header)) errors.push(`${path.relative(implementationRoot, file)} lacks ${key}`);
  }
  if (!/^document_class:\s*implementation_module\s*$/mu.test(header)) errors.push(`${path.relative(implementationRoot, file)} has the wrong document_class`);
  if (!/does_not_own:[\s\S]*(sequence|sequencing)[\s\S]*status[\s\S]*architecture doctrine[\s\S]*product authority/iu.test(header)) errors.push(`${path.relative(implementationRoot, file)} lacks the complete does_not_own boundary`);
  for (const match of header.matchAll(/^\s*-\s+(docs\/(?:architecture|decisions)\/[^\s]+)\s*$/gmu)) {
    if (!fs.existsSync(path.join(repoRoot, match[1]))) errors.push(`${path.relative(implementationRoot, file)} names missing owner ${match[1]}`);
  }
  if (/^#{1,6}\s+(?:Phase|Cut)\s+\d+/gmu.test(source)) errors.push(`${path.relative(implementationRoot, file)} contains an independently ordered Phase/Cut heading`);
  if (/^Status:\s*(?:active|verified|blocked|pending|evidence_ready)/gmiu.test(source)) errors.push(`${path.relative(implementationRoot, file)} contains live status prose`);
}

failWith("module-header check", errors);
process.stdout.write(`module-header check passed: ${files.length} subordinate modules\n`);

