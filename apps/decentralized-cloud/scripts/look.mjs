#!/usr/bin/env node
// LOOK AT ONE SURFACE — the deliberate counterpart to the gate.
//
// The gate answers "is anything I thought to check broken?". This answers "what does
// it actually look like?" — a different question, and the one that has found most of
// this programme's real defects: an array index rendered as evidence, half a table off
// the edge of a phone, a chip stretched into an 800px bar, a whole block of column-
// header styling that never matched an element. Every one of those was green in 170
// assertions and obvious in a picture.
//
// It waits for the surface's own content before shooting, so it never photographs a
// loading page and calls it the surface. That mistake has been made twice here.
//
//   SURFACE=receipts SEL=".t-receipts .trow" OUT=/tmp/r.png node scripts/look.mjs
//
// CLIP=x,y,w,h  crop instead of shooting the full page. A 30-row ledger shot in full
//               downsamples past legibility on the way to a reader, which is how a
//               scaling artifact once manufactured a finding in the mark rounds.
// STRIP=1       run THE PARAGRAPH TEST: hide every .prose paragraph and shoot what
//               remains. If a surface cannot say what it is without its sentences,
//               its facts are living in the prose instead of in the structure.
import { chromium } from "playwright";

const port = process.env.PORT || "4200";
const surface = process.env.SURFACE || "placement";
const sel = process.env.SEL || ".t-decision .trow";
const out = process.env.OUT || "/tmp/shot.png";
const clip = process.env.CLIP
  ? (([x, y, width, height]) => ({ x, y, width, height }))(process.env.CLIP.split(",").map(Number))
  : null;

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1180, height: 1000 } });
await page.goto(`http://127.0.0.1:${port}/#/${surface}`, { waitUntil: "domcontentloaded" });
// THE CAPTURE LABELS THE STATE IT CAPTURED, and the wait it observed.
//
// The contact sheet spent its whole life photographing three surfaces mid-load and
// presenting the result as the product; three cold readers reported those blanks back
// as defects. A picture that does not say which state it caught can be read as the
// loaded page by default, and it always will be.
const t0 = Date.now();
const arrived = await page.waitForSelector(sel, { timeout: 120000 })
  .then(() => true).catch(() => false);
const waited = Date.now() - t0;
// THE PARAGRAPH TEST, run rather than recalled. Hide every prose paragraph and look at
// what is left: if the surface cannot say what it is without its sentences, the facts
// are living in the prose instead of in the structure.
if (process.env.STRIP) {
  await page.addStyleTag({ content: ".prose { display: none !important; }" });
  await page.waitForTimeout(150);
}
// The label is BURNED INTO THE IMAGE, not printed beside it. A caption in a terminal
// does not travel with the picture; the picture is what gets looked at, pasted and
// relayed, so the state has to be part of it.
await page.evaluate(({ arrived, waited, sel }) => {
  const bar = document.createElement("div");
  bar.textContent = arrived
    ? `LOADED — "${sel}" present after ${waited}ms`
    : `STILL WAITING — "${sel}" never appeared in ${waited}ms. THIS IS NOT THE LOADED PAGE.`;
  bar.setAttribute("style",
    "position:fixed;left:0;right:0;bottom:0;z-index:2147483647;padding:6px 10px;" +
    "font:12px ui-monospace,monospace;color:#fff;" +
    `background:${arrived ? "#397554" : "#e40014"};`);
  document.body.appendChild(bar);
}, { arrived, waited, sel });

await page.screenshot({ path: out, ...(clip ? { clip } : { fullPage: true }) });
console.log(`${arrived ? "LOADED" : "STILL WAITING"} after ${waited}ms — wrote ${out}`);
await browser.close();
// A capture of a page that never loaded is not a failure of this script, but it must
// not exit clean: a green exit is how a waiting page gets treated as a result.
if (!arrived) process.exitCode = 2;
