#!/usr/bin/env node
// ioi-ds-sync-assets — copy the design-system's owned assets into a consumer's public/assets/.
//
// The design system is the single source of truth for brand/fonts/icons/logos/textures. Its CSS tokens
// and component bundle reference those assets by absolute /assets/... URLs, which a package cannot write
// into a consumer's public/ tree. This bin mirrors the package's assets into <consumer>/public/assets/
// so those references resolve, with zero hand-vendored duplication.
//
// Usage:
//   ioi-ds-sync-assets            # target = <cwd>/public/assets  (run from a consumer app dir)
//   ioi-ds-sync-assets <dir>      # target = <dir>/public/assets
// Wire it into a consumer as a "predev"/"prebuild" script so a fresh checkout is always asset-complete.
import { cpSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, "../assets");
const targetArg = process.argv.slice(2).find((a) => !a.startsWith("-"));
const DEST = join(targetArg ? resolve(targetArg) : process.cwd(), "public", "assets");

if (!existsSync(SRC)) {
  console.error(`[ioi-ds] assets source missing: ${SRC}`);
  process.exit(1);
}
mkdirSync(DEST, { recursive: true });
cpSync(SRC, DEST, { recursive: true });
console.log(`[ioi-ds] synced ${readdirSync(SRC).length} asset group(s) -> ${DEST}`);
