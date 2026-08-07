#!/usr/bin/env node
// Integrity gate for docs/architecture, docs/decisions, and docs/conformance.
//
// Deliberately small. It checks only what canon claims about itself, it owns no
// fixture corpus, and it is one file. `docs/engineering-lessons.md` records why
// that restraint matters: on 2026-08-05 this repo deleted 75 checker scripts
// because the proof apparatus had become a second product with its own defects.
// If this file ever needs fixtures or a second module, delete the rule instead.
//
//   node scripts/check-architecture-docs.mjs
//
// Rules:
//   1. every relative markdown link resolves
//   2. a backticked filename link label matches its target's basename
//   3. every canon doc declares both status-axis fields
//   4. every path named under `Implementation refs:` exists
//   5. a doc declaring `built` or `partial` names its code anchors (doc-classes.md)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ROOTS = ["docs/architecture", "docs/decisions", "docs/conformance"];
const failures = [];

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (full.endsWith(".md")) out.push(full);
  }
  return out;
}

const files = ROOTS.flatMap((r) => walk(path.join(root, r)));
const rel = (f) => path.relative(root, f);

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const dir = path.dirname(file);

  // 1 + 2 — links resolve, and labels are not stale filenames.
  for (const match of source.matchAll(/\[([^\]]*)\]\(([^)\s]+)\)/gu)) {
    const [, label, target] = match;
    if (/^[a-z][a-z0-9+.-]*:/iu.test(target) || target.startsWith("#")) continue;
    const withoutFragment = target.split("#")[0];
    if (withoutFragment === "") continue;

    let decoded;
    try {
      decoded = decodeURIComponent(withoutFragment);
    } catch {
      failures.push(`${rel(file)}: invalid link ${target}`);
      continue;
    }
    if (!fs.existsSync(path.resolve(dir, decoded))) {
      failures.push(`${rel(file)}: broken link ${target}`);
      continue;
    }
    const labelFile = label.match(/^`([^`]+\.md)`$/u)?.[1];
    if (labelFile && path.basename(labelFile) !== path.basename(decoded)) {
      failures.push(
        `${rel(file)}: stale link label \`${path.basename(labelFile)}\` points at ${path.basename(decoded)}`,
      );
    }
  }

  // 3 — the status axis every canon doc declares. ADRs carry their own header.
  if (file.includes(`${path.sep}docs${path.sep}architecture${path.sep}`) && !path.basename(file).startsWith("_")) {
    for (const field of ["Doctrine status:", "Implementation status:"]) {
      if (!source.includes(field)) failures.push(`${rel(file)}: missing \`${field}\``);
    }
  }

  // 5 — doc-classes.md: `built` and `partial` name their code anchors.
  const declared = source.match(/^Implementation status:\s*(\w+)/mu)?.[1];
  if (
    ["built", "partial"].includes(declared) &&
    !/^Implementation refs:/mu.test(source) &&
    !file.includes(`${path.sep}_archive${path.sep}`)
  ) {
    failures.push(`${rel(file)}: Implementation status \`${declared}\` declares no \`Implementation refs\``);
  }

  // 4 — declared implementation refs resolve.
  const block = source.match(/^Implementation refs:\n((?:\s+-\s+.*\n)+)/mu);
  for (const line of block?.[1].split("\n") ?? []) {
    const ref = line.match(/^\s+-\s+`?([^`\s]+)`?\s*$/u)?.[1];
    if (!ref || ref === "none") continue;
    if (!fs.existsSync(path.resolve(root, ref))) {
      failures.push(`${rel(file)}: Implementation ref does not exist — ${ref}`);
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  console.error(`\n${failures.length} architecture-doc integrity failures`);
  process.exit(1);
}
console.log(`Architecture docs OK — ${files.length} files, 5 rules.`);
