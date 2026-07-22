// Generated-capture harness: screenshots real daemon-served product surfaces
// per docs/shot-manifest.json. No staged screenshots — if a surface isn't
// reachable and real, the shot fails; it is never faked.
//
// Usage:
//   IOI_SERVE_URL=http://127.0.0.1:<port> node tools/capture-screens.mjs [ids…]
//     --all                  capture every confirmed shot
//     --include-unconfirmed  also attempt shots marked confirm:true
//
// The serve MUST be a real daemon serve of the owned product UI with the
// seeded demo estate loaded and WITHOUT test flags (standing rule).
import { readFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { chromium } = createRequire(join(ROOT, "package.json"))("playwright");

const BASE = process.env.IOI_SERVE_URL;
if (!BASE) {
  console.error("capture: IOI_SERVE_URL is required (real daemon serve, seeded estate, no test flags)");
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(join(ROOT, "docs/shot-manifest.json"), "utf8"));
const args = process.argv.slice(2);
const includeUnconfirmed = args.includes("--include-unconfirmed");
const ids = args.filter((a) => !a.startsWith("--"));
const wanted = manifest.shots.filter(
  (s) =>
    (ids.length ? ids.includes(s.id) : true) &&
    (includeUnconfirmed || !s.confirm)
);
if (!wanted.length) {
  console.error("capture: no shots selected (unconfirmed shots need --include-unconfirmed)");
  process.exit(1);
}

const OUT_DIR = join(ROOT, "src/assets/product");
mkdirSync(OUT_DIR, { recursive: true });

const browser = await chromium.launch();
let failed = 0;
for (const shot of wanted) {
  const d = { ...manifest.defaults, ...shot };
  const page = await browser.newPage({
    viewport: d.viewport,
    deviceScaleFactor: d.deviceScaleFactor,
  });
  const url = BASE + shot.path;
  try {
    if (!shot.path) throw new Error("path not yet confirmed");
    const resp = await page.goto(url, { waitUntil: "networkidle", timeout: 30000 });
    if (!resp || !resp.ok()) throw new Error(`HTTP ${resp ? resp.status() : "no response"}`);
    if (new URL(page.url()).pathname === "/" && shot.path !== "/") {
      throw new Error("redirected to / — surface not live");
    }
    await page.waitForTimeout(d.settleMs);
    await page.screenshot({ path: join(OUT_DIR, shot.out), fullPage: false });
    console.log(`✓ ${shot.id} → src/assets/product/${shot.out}`);
  } catch (e) {
    failed++;
    console.error(`✕ ${shot.id} (${url}): ${e.message}`);
  } finally {
    await page.close();
  }
}
await browser.close();
if (failed) {
  console.error(`capture: ${failed} shot(s) failed — surfaces must be real before they ship`);
  process.exit(1);
}
