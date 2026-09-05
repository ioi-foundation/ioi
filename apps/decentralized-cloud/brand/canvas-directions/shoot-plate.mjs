#!/usr/bin/env node
// Shoot the plate at deviceScaleFactor 1. Nothing is magnified and nothing is
// downsampled: 16px on the plate is sixteen pixels in the PNG, which is the only way a
// reader's answer at 16px means anything.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const src = "file://" + path.join(HERE, "plates/marks-head-to-head.html");
const out = path.join(HERE, "plates/marks-head-to-head.png");

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1180, height: 1000 }, deviceScaleFactor: 1 });
await page.goto(src, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
await page.screenshot({ path: out, fullPage: true });
console.log("wrote", out);
await browser.close();
