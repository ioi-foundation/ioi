#!/usr/bin/env node
// import-upstream-export — refresh @ioi/design-system from an upstream design-system dist export.
//
// The component source + bundle generator live upstream; the upstream only ships compiled "portable
// package" dist exports (_ds_bundle.js + styles.css + tokens/ + assets/). Each export arrives
// un-neutralized (a per-export, hashed `window.<Brand>DesignSystem_<hash>` namespace, brand strings in
// identifiers + comments) and assumes a UMD global React with relative asset paths. This script applies
// the deterministic adaptations we otherwise repeat by hand on every refresh, so the result is always
// source-neutral and Vite/ESM-consumable:
//   1. Brand neutralization  — <Brand>DesignSystem_<hash> -> IoiDesignSystem (stable; consumers depend
//      on window.IoiDesignSystem), <Brand>Xxx identifiers -> IoiXxx, prose <Brand> -> IOI.
//   2. React prepend         — `const React = window.React;` so the bundle resolves React under ESM.
//   3. Asset absolutization  — url(../assets/…) / url("../assets/…") -> /assets/… (served from public/).
// It then asserts zero brand residue before writing, and never copies the upstream's branded README.
//
// Usage: node scripts/import-upstream-export.mjs <path-to-export-dist-dir>
//        (the dir containing _ds_bundle.js, styles.css, tokens/, assets/)
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(here, "..");
const SRC = process.argv[2] ? resolve(process.argv[2]) : null;

const die = (m) => { console.error(`[import-export] FAIL: ${m}`); process.exit(1); };
if (!SRC) die("pass the path to an upstream export's dist dir (with _ds_bundle.js, styles.css, tokens/, assets/)");
for (const req of ["_ds_bundle.js", "styles.css", "tokens", "assets"]) {
  if (!existsSync(join(SRC, req))) die(`export is missing ${req} at ${SRC}`);
}

// --- brand neutralization -------------------------------------------------
// Detect the export's namespace from the @ds-bundle header (robust to the per-export hash suffix).
const rawBundle = readFileSync(join(SRC, "_ds_bundle.js"), "utf8");
const nsMatch = rawBundle.match(/"namespace"\s*:\s*"([A-Za-z0-9_]+)"/);
const ns = nsMatch?.[1]; // the export's hashed namespace token, e.g. <Brand>DesignSystem_<hash>
const brand = ns?.match(/^([A-Za-z]+?)DesignSystem/)?.[1]; // the export's brand prefix
if (!ns || !brand) die(`could not detect namespace/brand from @ds-bundle header (found ns=${ns})`);

const neutralizeCode = (s) =>
  s
    .split(ns).join("IoiDesignSystem")                         // window.<NS>/header -> stable namespace
    .replace(new RegExp(`\\b${brand}([A-Z][A-Za-z0-9_]*)`, "g"), "Ioi$1") // <Brand>Button -> IoiButton
    .replace(new RegExp(`\\b${brand}\\b`, "g"), "IOI")         // prose "<Brand> ..." -> "IOI ..."
    .replace(new RegExp(`\\b${brand.toLowerCase()}\\b`, "g"), "ioi"); // lowercase brand (e.g. a brand domain) -> ioi

const absolutize = (s) =>
  s.replace(/url\((["']?)(?:\.\.\/)+assets\//g, "url($1/assets/"); // ../assets|../../assets -> /assets

// --- bundle: neutralize + React-prepend + absolutize ----------------------
let bundle = absolutize(neutralizeCode(rawBundle));
const REACT_SHIM = "const React = window.React;";
if (!bundle.startsWith(REACT_SHIM)) bundle = `${REACT_SHIM}\n${bundle}`;
mkdirSync(join(PKG, "bundle"), { recursive: true });
writeFileSync(join(PKG, "bundle", "_ds_bundle.js"), bundle);

// --- styles.css + tokens: neutralize comments + absolutize asset urls ------
writeFileSync(join(PKG, "styles.css"), absolutize(neutralizeCode(readFileSync(join(SRC, "styles.css"), "utf8"))));
mkdirSync(join(PKG, "tokens"), { recursive: true });
for (const f of readdirSync(join(SRC, "tokens")).filter((f) => f.endsWith(".css"))) {
  writeFileSync(join(PKG, "tokens", f), absolutize(neutralizeCode(readFileSync(join(SRC, "tokens", f), "utf8"))));
}

// --- assets: additive merge (NOT replace) ---------------------------------
// The export is not an asset superset: the bundle's site components reference app-supplied content the
// upstream omits (badges/, logos/models, logos/tools, brand/ioi-logo.svg). Merge refreshes the
// export-provided assets while preserving those extras; report extras so coverage is never silent.
const walk = (root, base = root, acc = []) => {
  if (!existsSync(root)) return acc;
  for (const e of readdirSync(root, { withFileTypes: true })) {
    const p = join(root, e.name);
    e.isDirectory() ? walk(p, base, acc) : acc.push(p.slice(base.length + 1));
  }
  return acc;
};
const exportAssets = new Set(walk(join(SRC, "assets")));
const extras = walk(join(PKG, "assets")).filter((f) => !exportAssets.has(f));
cpSync(join(SRC, "assets"), join(PKG, "assets"), { recursive: true });

// --- assert source-neutrality before declaring success --------------------
// Residue detector is built from the runtime-detected brand (so no upstream brand literal lives in this
// source): any leftover brand word or a still-hashed namespace fails the run before anything is trusted.
const residue = new RegExp(`\\b${brand}\\b|DesignSystem_[a-f0-9]`, "i");
const written = ["bundle/_ds_bundle.js", "styles.css", ...readdirSync(join(PKG, "tokens")).map((f) => `tokens/${f}`)];
const leaks = written.filter((rel) => residue.test(readFileSync(join(PKG, rel), "utf8")));
if (leaks.length) die(`brand residue remains in: ${leaks.join(", ")} (neutralization incomplete)`);

console.log(`[import-export] refreshed @ioi/design-system from ${SRC}`);
console.log(`[import-export]   namespace ${ns} -> IoiDesignSystem; brand ${brand} -> Ioi/IOI/ioi`);
console.log(`[import-export]   assets: ${exportAssets.size} from export, ${extras.length} app-origin preserved; source-neutral OK`);
if (extras.length) console.log(`[import-export]   app-origin (not in export): ${extras.join(", ")}`);
