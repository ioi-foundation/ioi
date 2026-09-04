#!/usr/bin/env node
// Brand canvas build step.
//
// The artboards are authored in `src/` with font placeholders so the repo's real
// faces — IOI Display for the wordmark, ABC Diatype for UI, ABC Diatype Mono for
// labels — end up embedded as data: URIs. A design canvas artboard has no network
// egress beyond Google Fonts, so a self-hosted face only renders when it rides
// inline. Placeholders keep the base64 out of the authored source.
//
// Usage: node apps/decentralized-cloud/brand/build-artboards.mjs

import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const FONTS = path.join(REPO, "packages/design-system/assets/fonts");
const SRC = path.join(HERE, "src");
const OUT = path.join(HERE, "canvas");

const FACES = {
  __B64_IOI__: "IOI.ttf",
  __B64_SANS__: "ABCDiatype-Regular.woff2",
  __B64_SANS_BOLD__: "ABCDiatype-Bold.woff2",
  __B64_MONO__: "ABCDiatypeSemi-Mono-Regular.woff2",
  __B64_MONO_MED__: "ABCDiatypeSemi-Mono-Medium.woff2",
};

const b64 = {};
for (const [token, file] of Object.entries(FACES)) {
  b64[token] = readFileSync(path.join(FONTS, file)).toString("base64");
}

mkdirSync(OUT, { recursive: true });

let written = 0;
for (const name of readdirSync(SRC)) {
  const source = readFileSync(path.join(SRC, name), "utf8");
  let out = source;
  for (const [token, value] of Object.entries(b64)) {
    out = out.split(token).join(value);
  }
  const leftover = out.match(/__B64_[A-Z_]+__/);
  if (leftover) throw new Error(`${name}: unresolved font placeholder ${leftover[0]}`);
  writeFileSync(path.join(OUT, name), out);
  written += 1;
}

console.log(`brand artboards: ${written} written to ${path.relative(REPO, OUT)}`);
