// COPIES THE OWNER'S BRAND ASSETS from brand/mark/source/ into public/brand/, and
// with --check verifies every served file is a byte-for-byte copy of its source.
//
// Nothing is generated. The owner delivered the identity complete
// (brand-identity-standalone.html, 2026-09-07) and its decoded assets are the
// sources of record; a served file that differs from its source is a hand edit that
// goes red before it ships. The one derivation is the favicon, which is the
// reduction glyph under the name browsers look for. Two ties bind the shell to the
// files: CLOUD_PATH in mark.mjs must appear verbatim in mark-dark.svg, and the
// wordmark transform must appear verbatim in lockup-dark.svg.
//
// Usage: node apps/decentralized-cloud/brand/mark/build-assets.mjs [--check]

import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BRAND_FILES, FAVICON_SOURCE, CLOUD_PATH, LOCKUP_WORDMARK_TRANSFORM, CUT_POLYGON } from "./mark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, "source");
const OUT = path.join(HERE, "../../public/brand");

const markDark = readFileSync(path.join(SRC, "mark-dark.svg"), "utf8");
if (!markDark.includes(`d="${CLOUD_PATH}"`)) throw new Error("mark.mjs CLOUD_PATH is not the path in source/mark-dark.svg");
if (!markDark.includes(`points="${CUT_POLYGON}"`)) throw new Error("mark.mjs CUT_POLYGON is not the polygon in source/mark-dark.svg");
const lockupDark = readFileSync(path.join(SRC, "lockup-dark.svg"), "utf8");
if (!lockupDark.includes(`transform="${LOCKUP_WORDMARK_TRANSFORM}"`)) throw new Error("mark.mjs LOCKUP_WORDMARK_TRANSFORM is not the transform in source/lockup-dark.svg");

const PAIRS = [...BRAND_FILES.map((f) => [f, f]), [FAVICON_SOURCE, "favicon.svg"]];

// THE BRAND PAGE, /brand/, is the owner's page (source/brand-page.html) with the
// bundle's asset ids replaced by the file names above and its two about:blank
// iframes pointed at the served animated pages. The text is not edited. It is
// derived here so --check covers it like every other served file.
const ID_TO_FILE = {
  "0171e79d-c7cf-4cf7-877a-b51666a1ffc5": "lockup-dark.svg",
  "0e234504-0a92-4cd1-a057-d61ee5445d70": "lockup-light.svg",
  "10147e44-ca76-4a6d-be38-45be027af772": "mark-dark.svg",
  "497290d2-3bc8-4b06-8d2b-3f669cd04924": "mark-light.svg",
  "7ed1b7b3-85ed-47c9-b84e-65b3ddd4c8a0": "mark-mono-white.svg",
  "75b0e488-0c65-4964-85de-3723f6c20bba": "mark-mono-navy.svg",
  "36e6a047-b15c-4210-a038-5528999a1d4b": "glyph.svg",
  "about:blank#50ae46b9-a64d-4775-b88e-e3214cee0b05": "hero-3d.html",
  "about:blank#f37e98af-e83e-4a7e-9700-ce458d82e1c3": "mark-animated.html",
  "./brand/mark-animated.html": "mark-animated.html",
  "./cloud-hover-3d.html": "hero-3d.html",
};
function brandPage() {
  let page = readFileSync(path.join(SRC, "brand-page.html"), "utf8");
  for (const [id, file] of Object.entries(ID_TO_FILE)) page = page.split(id).join(file);
  const helmet = /<helmet>([\s\S]*?)<\/helmet>/.exec(page);
  // The template carries the bundler's own doctype and head (its support script);
  // neither is the owner's page and neither is served.
  const body = page.replace(/<!DOCTYPE html>/gi, "").replace(/<head>[\s\S]*?<\/head>/g, "")
    .replace(/<\/?x-dc>/g, "").replace(/<helmet>[\s\S]*?<\/helmet>/, "").replace(/<\/?body>|<\/?html>/g, "").trim();
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
    "<title>decentralized.cloud — brand identity</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"/brand/favicon.svg\">\n" +
    "<!-- The owner's brand page (brand/mark/source/brand-page.html), verbatim in its text; the asset references point at the\n" +
    "     same-named files served beside it, every one a byte-for-byte copy of the owner's source. The WebGL hero loads three.js\n" +
    "     from unpkg through the owner's pinned import map, so it needs the network; the SVG animated mark does not. -->\n" +
    (helmet ? helmet[1].trim() + "\n" : "") + "</head>\n<body>\n" + body + "\n</body>\n</html>\n";
}

const check = process.argv.includes("--check");
mkdirSync(OUT, { recursive: true });
const drift = [];
for (const [from, to] of PAIRS) {
  const src = path.join(SRC, from), dst = path.join(OUT, to);
  if (!existsSync(src)) throw new Error(`source asset missing: ${from}`);
  if (check) {
    const a = readFileSync(src), b = existsSync(dst) ? readFileSync(dst) : null;
    if (!b || !a.equals(b)) drift.push(to);
  } else {
    copyFileSync(src, dst);
  }
}
const indexPath = path.join(OUT, "index.html");
if (check) {
  if (!existsSync(indexPath) || readFileSync(indexPath, "utf8") !== brandPage()) drift.push("index.html");
} else {
  writeFileSync(indexPath, brandPage());
}
if (check) {
  if (drift.length) {
    console.error(`brand assets drifted from brand/mark/source: ${drift.join(", ")} — run build-assets.mjs`);
    process.exit(1);
  }
  console.log(`brand assets: ${PAIRS.length} files are byte-for-byte copies of the owner's sources, and /brand/ is their page`);
} else {
  console.log(`copied ${PAIRS.length} files and wrote index.html to ${OUT}`);
}
