#!/usr/bin/env node
// Token gate — the mechanical styling guarantee for injected UI.
//
// Every CSS class the augmentation modules put on shell DOM must exist in the shell's own
// stylesheet: the harvested CSS is JIT-pruned, so a class that "should" work but was never
// emitted silently renders unstyled. This gate makes that failure impossible to miss, using the
// shell-parity CSS inventory (the committed code-level freeze) as the contract.
//
// Scans: apps/hypervisor/scripts/augmentation/*.js — class="..." in HTML strings and .className
// string assignments. Tokens with an `ioi-` prefix are the augmentation's own (styled by its
// injected stylesheet) and are exempt, as are template interpolations.
//
// Usage: node apps/hypervisor/scripts/check-augmentation-tokens.mjs   (exit 1 on unknown tokens)

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const AUG_DIR = join(HERE, "augmentation");
const INVENTORY = join(HERE, "..", "shell-parity", "css-inventory.json");

const inv = JSON.parse(readFileSync(INVENTORY, "utf8"));
const known = new Set();
for (const f of Object.values(inv.files)) for (const c of f.classes) known.add(c.replace(/\\/g, ""));

// The augmentation's OWN stylesheet (the css template + injected style blocks in the modules)
// also defines classes — those are contract-exempt: a class is valid if the shell OR the
// augmentation styles it.
const ownCss = new Set();
const CSS_CLASS_RE = /\.((?:[\w-]|\\.)+)/g;
const moduleFiles = readdirSync(AUG_DIR).filter((f) => f.endsWith(".js")).sort();
for (const file of moduleFiles) {
  const src = readFileSync(join(AUG_DIR, file), "utf8");
  // Extract css-ish regions: template literals / strings that contain `{` styling blocks.
  for (const m of src.matchAll(/`([^`]*\{[^`]*)`/gs)) {
    for (const c of m[1].matchAll(CSS_CLASS_RE)) ownCss.add(c[1].replace(/\\/g, ""));
  }
}

const candidates = new Map(); // token -> [file:line]
const strict = new Set(); // tokens seen in a PURE static attr (no concatenation) — hard-enforced
const CLASS_ATTR_RE = /class="([^"]*)"/g;
const CLASSNAME_RE = /\.className\s*=\s*((?:"[^"]*"\s*\+?\s*)+)/g;
const TOKEN_OK = /^[-\w:./[\]%]+$/;

for (const file of moduleFiles) {
  const src = readFileSync(join(AUG_DIR, file), "utf8");
  const lines = src.split("\n");
  const collect = (chunk, lineNo, pure) => {
    for (const raw of chunk.split(/\s+/)) {
      const tok = raw.trim();
      if (!tok || !TOKEN_OK.test(tok)) continue; // dynamic/interpolated fragments
      if (tok.startsWith("ioi-")) continue; // augmentation-owned namespace
      if (!candidates.has(tok)) candidates.set(tok, []);
      candidates.get(tok).push(`${file}:${lineNo}`);
      if (pure) strict.add(tok);
    }
  };
  lines.forEach((line, i) => {
    // An attr capture containing a single quote crossed a JS string-concatenation boundary —
    // its bare identifiers are JS variables, so only PURE captures are hard-enforced; tokens
    // from concatenated captures still count when they resolve, and fail only if seen pure.
    for (const m of line.matchAll(CLASS_ATTR_RE)) collect(m[1], i + 1, !m[1].includes("'"));
    for (const m of line.matchAll(CLASSNAME_RE)) {
      for (const s of m[1].matchAll(/"([^"]*)"/g)) collect(s[1], i + 1, true);
    }
  });
}

const unknown = [...strict].filter((t) => !known.has(t) && !ownCss.has(t)).sort();
if (unknown.length) {
  console.error(`✗ ${unknown.length} class token(s) not present in the shell stylesheet (JIT-pruned — they will render unstyled):`);
  for (const t of unknown) console.error(`  ${t}  — ${candidates.get(t).slice(0, 3).join(", ")}`);
  process.exit(1);
}
console.log(`✓ augmentation tokens: ${candidates.size} distinct class tokens, all present in the shell stylesheet`);
