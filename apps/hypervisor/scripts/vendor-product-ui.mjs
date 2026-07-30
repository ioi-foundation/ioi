#!/usr/bin/env node
// Vendor the product shell into an OWNED, editable source tree (phase 1 of shell ownership).
//
// This is adoption, not recreation: the running bundle's own code becomes the source tree —
// beautified for editability, proven equivalent at the AST level. Ownership then grows by
// editing this tree in place (Ship of Theseus), never by rebuilding from observation, so there
// is no "current version vs recreated version" gap for discrepancies to hide in.
//
//   product-ui/public/**  ──▶  product-ui/owned/public/**
//     · app .js chunks       → prettier(babel) beautified, gated by esbuild AST-equivalence:
//                              minify(original) must equal minify(beautified) BYTE-FOR-BYTE.
//     · vendor-*.js          → verbatim (third-party mega-bundle; never an ownership target —
//                              it is this tree's node_modules, not its src/).
//     · .css                 → prettier beautified, same esbuild gate (loader css).
//     · everything else      → verbatim copy.
//
// OWNED EDITS ARE SACRED: a file whose on-disk content no longer matches what this script last
// generated (per vendor-manifest.json) is a deliberate ownership edit — it is preserved and
// reported, never clobbered. If its upstream original ALSO changed, that's a conflict to
// reconcile by hand.
//
// Usage: node apps/hypervisor/scripts/vendor-product-ui.mjs [--check]
//   default: build/update the owned tree + manifest
//   --check: verify manifest coverage + re-prove the AST gate for every beautified file; exit 1
//            on any missing file, unproven equivalence, or upstream/owned conflict.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "product-ui", "public");
const DEST = join(HERE, "..", "product-ui", "owned", "public");
const MANIFEST_PATH = join(HERE, "..", "product-ui", "owned", "vendor-manifest.json");
const CHECK = process.argv.includes("--check");

const require_ = (await import("node:module")).createRequire(import.meta.url);
const esbuild = require_(join(process.cwd(), "node_modules", "esbuild"));
const prettier = await import("prettier");

const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const walk = (dir) => readdirSync(dir).flatMap((n) => {
  const p = join(dir, n);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

const isVerbatimJs = (rel) => /(^|\/)vendor-[^/]*\.js$/.test(rel);
const jsGate = async (a, b) => {
  const [ma, mb] = await Promise.all([
    esbuild.transform(a, { minify: true, target: "esnext" }),
    esbuild.transform(b, { minify: true, target: "esnext" }),
  ]);
  return ma.code === mb.code;
};
const cssGate = async (a, b) => {
  const [ma, mb] = await Promise.all([
    esbuild.transform(a, { loader: "css", minify: true }),
    esbuild.transform(b, { loader: "css", minify: true }),
  ]);
  return ma.code === mb.code;
};

const prevManifest = existsSync(MANIFEST_PATH) ? JSON.parse(readFileSync(MANIFEST_PATH, "utf8")).files : {};
const files = walk(SRC).sort();
const manifest = {};
const report = { beautified: 0, verbatim: 0, preserved_owned_edits: [], conflicts: [], gate_failures: [], errors: [] };

for (const f of files) {
  const rel = relative(SRC, f);
  const destPath = join(DEST, rel);
  const srcBuf = readFileSync(f);
  const srcSha = sha(srcBuf);
  const prev = prevManifest[rel];

  if (CHECK) {
    // Check mode is MANIFEST-DRIVEN: the manifest says what each owned file is supposed to be;
    // we re-prove exactly that claim (never re-derive policy — a file that legitimately fell
    // back to verbatim must be checked as verbatim, and an owned edit is a recorded fact).
    if (!prev) { report.errors.push("unvendored upstream file: " + rel); continue; }
    if (!existsSync(destPath)) { report.errors.push("missing owned file: " + rel); continue; }
    const curBuf = readFileSync(destPath);
    const curSha = sha(curBuf);
    if (prev.mode === "owned-edit" || curSha !== prev.out_sha256) {
      // A deliberate ownership edit (recorded, or made since the last vendor run).
      if (srcSha !== prev.src_sha256) report.conflicts.push(rel);
      report.preserved_owned_edits.push(rel);
      manifest[rel] = { ...prev, mode: "owned-edit", src_sha256: srcSha, out_sha256: curSha };
      continue;
    }
    if (prev.mode === "beautified") {
      const okGate = rel.endsWith(".css")
        ? await cssGate(srcBuf.toString("utf8"), curBuf.toString("utf8"))
        : await jsGate(srcBuf.toString("utf8"), curBuf.toString("utf8"));
      if (!okGate) report.gate_failures.push(rel + " (owned tree no longer AST-equal)");
    } else if (curSha !== srcSha) {
      report.errors.push("verbatim file diverged without owned-edit record: " + rel);
    }
    if (srcSha !== prev.src_sha256) report.errors.push("upstream changed since last vendor run: " + rel);
    manifest[rel] = prev;
    continue;
  }

  // Preserve deliberate ownership edits: on-disk owned file differs from what we last generated.
  if (prev && existsSync(destPath)) {
    const curSha = sha(readFileSync(destPath));
    if (curSha !== prev.out_sha256 || prev.mode === "owned-edit") {
      if (srcSha !== prev.src_sha256) report.conflicts.push(rel); // upstream AND owned both moved
      report.preserved_owned_edits.push(rel);
      manifest[rel] = { ...prev, mode: "owned-edit", src_sha256: srcSha, out_sha256: curSha };
      continue;
    }
    if (srcSha === prev.src_sha256) { manifest[rel] = prev; continue; } // up to date
  }

  const isJs = rel.endsWith(".js") || rel.endsWith(".mjs");
  const isCss = rel.endsWith(".css");
  let mode = "verbatim";
  let outBuf = srcBuf;
  let gate = "n/a";
  if (isJs && !isVerbatimJs(rel)) {
    try {
      const pretty = await prettier.format(srcBuf.toString("utf8"), { parser: "babel", printWidth: 120 });
      if (await jsGate(srcBuf.toString("utf8"), pretty)) { outBuf = Buffer.from(pretty); mode = "beautified"; gate = "esbuild-ast-equal"; }
      else { report.gate_failures.push(rel); }
    } catch (e) { report.errors.push(rel + " :: " + String(e.message).slice(0, 120)); }
  } else if (isCss) {
    try {
      const pretty = await prettier.format(srcBuf.toString("utf8"), { parser: "css", printWidth: 120 });
      if (await cssGate(srcBuf.toString("utf8"), pretty)) { outBuf = Buffer.from(pretty); mode = "beautified"; gate = "esbuild-ast-equal"; }
      else { report.gate_failures.push(rel); }
    } catch (e) { report.errors.push(rel + " :: " + String(e.message).slice(0, 120)); }
  }

  mkdirSync(dirname(destPath), { recursive: true });
  if (mode === "verbatim") copyFileSync(f, destPath); else writeFileSync(destPath, outBuf);
  manifest[rel] = { mode, src_sha256: srcSha, out_sha256: sha(mode === "verbatim" ? srcBuf : outBuf), gate };
  if (mode === "beautified") report.beautified++; else report.verbatim++;
}

if (!CHECK) {
  mkdirSync(dirname(MANIFEST_PATH), { recursive: true });
  writeFileSync(MANIFEST_PATH, JSON.stringify({ src: "product-ui/public", dest: "product-ui/owned/public", files: manifest }, null, 1) + "\n");
}

const bad = report.gate_failures.length + report.errors.length + report.conflicts.length;
console.log(`${CHECK ? "checked" : "vendored"} ${files.length} files — beautified ${CHECK ? Object.values(manifest).filter((m) => m.mode === "beautified").length : report.beautified} · verbatim ${CHECK ? Object.values(manifest).filter((m) => m.mode === "verbatim").length : report.verbatim} · owned edits preserved ${report.preserved_owned_edits.length}`);
if (report.preserved_owned_edits.length) console.log("  owned edits: " + report.preserved_owned_edits.join(", "));
if (report.conflicts.length) console.error("  CONFLICTS (upstream + owned both changed): " + report.conflicts.join(", "));
if (report.gate_failures.length) console.error("  GATE FAILURES (kept verbatim): " + report.gate_failures.join(", "));
if (report.errors.length) console.error("  errors: " + report.errors.join(" | "));
if (CHECK && bad) { console.error("vendor check: FAIL"); process.exit(1); }
if (CHECK) console.log("vendor check: OK — every beautified file re-proven AST-equal to its original");
