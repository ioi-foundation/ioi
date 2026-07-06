#!/usr/bin/env node
// Shell freeze — CODE-LEVEL layer (phase 0a of the shell-ownership program).
//
// Enumerates every stone in the product shell at the artifact level, so nothing can change
// silently: a sha256 manifest of every file the shell serves, plus a full CSS inventory —
// every class selector, every @keyframes name, every animation/transition declaration —
// because subtle motion (loading spinners, fades) lives in code even when a screenshot
// can't catch it mid-frame.
//
// Output (committed — this IS the freeze):
//   apps/hypervisor/shell-parity/assets-manifest.json
//   apps/hypervisor/shell-parity/css-inventory.json
//
// Usage: node apps/hypervisor/scripts/shell-freeze-assets.mjs [--check]
//   default: (re)write the freeze
//   --check: recompute and diff against the committed freeze; exit 1 on drift

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(HERE, "..", "product-ui", "public");
const OUT_DIR = join(HERE, "..", "shell-parity");
const CHECK = process.argv.includes("--check");

const sha = (buf) => createHash("sha256").update(buf).digest("hex");

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

// ---- 1. Asset manifest: every served file, hashed. ----
const files = walk(PUBLIC).sort();
const manifest = {};
for (const f of files) {
  const rel = relative(PUBLIC, f);
  const buf = readFileSync(f);
  manifest[rel] = { sha256: sha(buf), bytes: buf.length };
}

// ---- 2. CSS inventory: classes, keyframes, animation/transition declarations. ----
// Parsed lexically (comment/string aware enough for compiled CSS) — the goal is a stable,
// diffable inventory of every motion- and style-bearing construct, not a full CSS engine.
const cssFiles = files.filter((f) => f.endsWith(".css"));
const inventory = { files: {}, totals: {} };
// Class name = word chars/hyphens plus ESCAPED specials (\:, \[, \/ …); an unescaped `:` is a
// pseudo-class boundary, not part of the name — so `.hover\:x:hover` yields `hover\:x`.
const CLASS_RE = /\.((?:[\w-]|\\.)+)/g;
const KEYFRAMES_RE = /@(?:-webkit-)?keyframes\s+([\w-]+)/g;
const ANIM_DECL_RE = /(?:^|[;{])\s*(animation(?:-[a-z-]+)?)\s*:\s*([^;}]+)/g;
const TRANS_DECL_RE = /(?:^|[;{])\s*(transition(?:-[a-z-]+)?)\s*:\s*([^;}]+)/g;
for (const f of cssFiles) {
  const rel = relative(PUBLIC, f);
  const css = readFileSync(f, "utf8");
  const classes = new Set(); const keyframes = new Set(); const animations = new Set(); const transitions = new Set();
  for (const m of css.matchAll(CLASS_RE)) classes.add(m[1]);
  for (const m of css.matchAll(KEYFRAMES_RE)) keyframes.add(m[1]);
  for (const m of css.matchAll(ANIM_DECL_RE)) animations.add(`${m[1]}: ${m[2].trim()}`);
  for (const m of css.matchAll(TRANS_DECL_RE)) transitions.add(`${m[1]}: ${m[2].trim()}`);
  inventory.files[rel] = {
    classes: [...classes].sort(),
    keyframes: [...keyframes].sort(),
    animation_declarations: [...animations].sort(),
    transition_declarations: [...transitions].sort(),
  };
}
inventory.totals = {
  files: files.length,
  css_files: cssFiles.length,
  classes: Object.values(inventory.files).reduce((n, f) => n + f.classes.length, 0),
  keyframes: Object.values(inventory.files).reduce((n, f) => n + f.keyframes.length, 0),
  animation_declarations: Object.values(inventory.files).reduce((n, f) => n + f.animation_declarations.length, 0),
  transition_declarations: Object.values(inventory.files).reduce((n, f) => n + f.transition_declarations.length, 0),
};

const manifestJson = JSON.stringify({ root: "product-ui/public", files: manifest }, null, 1) + "\n";
const inventoryJson = JSON.stringify(inventory, null, 1) + "\n";

if (CHECK) {
  let drift = 0;
  const diff = (name, next) => {
    const p = join(OUT_DIR, name);
    if (!existsSync(p)) { console.error(`MISSING freeze file ${name}`); drift++; return; }
    const prev = readFileSync(p, "utf8");
    if (prev !== next) {
      console.error(`DRIFT in ${name}`);
      const a = JSON.parse(prev), b = JSON.parse(next);
      if (name === "assets-manifest.json") {
        const pa = Object.keys(a.files), pb = Object.keys(b.files);
        for (const k of pb.filter((x) => !pa.includes(x))) console.error(`  + ${k}`);
        for (const k of pa.filter((x) => !pb.includes(x))) console.error(`  - ${k}`);
        for (const k of pa.filter((x) => pb.includes(x) && a.files[x].sha256 !== b.files[x].sha256)) console.error(`  ~ ${k}`);
      }
      drift++;
    }
  };
  diff("assets-manifest.json", manifestJson);
  diff("css-inventory.json", inventoryJson);
  if (drift) { console.error("shell asset freeze: DRIFT"); process.exit(1); }
  console.log(`shell asset freeze: intact (${files.length} files, ${inventory.totals.classes} classes, ${inventory.totals.keyframes} keyframes)`);
} else {
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, "assets-manifest.json"), manifestJson);
  writeFileSync(join(OUT_DIR, "css-inventory.json"), inventoryJson);
  console.log(`froze ${files.length} assets · ${inventory.totals.classes} classes · ${inventory.totals.keyframes} keyframes · ${inventory.totals.animation_declarations} animation decls · ${inventory.totals.transition_declarations} transition decls`);
}
