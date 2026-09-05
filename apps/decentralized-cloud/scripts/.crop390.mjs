// Crop a 390px surface at TRUE scale. A 390x4639 full-page shot downsamples ~2.3x in
// delivery, which is the scaling artifact that once manufactured a mark finding — so
// the phone width has to be inspected in bands, unscaled.
import { chromium } from "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs";

const port = process.env.PORT || "4211";
const surface = process.env.SURFACE || "catalog";
const sel = process.env.SEL || ".t-catalog .trow";
const bands = (process.env.BANDS || "0,900;900,900;1800,900").split(";");
const out = process.env.OUT || "/tmp/band";

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 390, height: 900 }, deviceScaleFactor: 1 });
await page.goto(`http://127.0.0.1:${port}/#/${surface}`, { waitUntil: "domcontentloaded" });
const ok = await page.waitForSelector(sel, { timeout: 120000 }).then(() => true).catch(() => false);
console.log(ok ? "LOADED" : "STILL WAITING");
await page.waitForTimeout(400);
for (const b of bands) {
  const [y, h] = b.split(",").map(Number);
  const f = `${out}-${y}.png`;
  // fullPage, so a band below the viewport is reachable — a clip alone is bounded by
  // the visible frame and throws once y exceeds it.
  await page.screenshot({ path: f, fullPage: true, clip: { x: 0, y, width: 390, height: h } });
  console.log("wrote", f);
}
await browser.close();
