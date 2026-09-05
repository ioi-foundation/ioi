// Throwaway: screenshot one surface after its read completes, so the decision table
// can be LOOKED at rather than inferred from a green assertion.
import { chromium } from "playwright";

const port = process.env.PORT || "4200";
const surface = process.env.SURFACE || "placement";
const sel = process.env.SEL || ".t-decision .trow";
const out = process.env.OUT || "/tmp/shot.png";

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1180, height: 1000 } });
await page.goto(`http://127.0.0.1:${port}/#/${surface}`, { waitUntil: "domcontentloaded" });
await page.waitForSelector(sel, { timeout: 120000 });
await page.screenshot({ path: out, fullPage: true });
console.log("wrote", out);
await browser.close();
