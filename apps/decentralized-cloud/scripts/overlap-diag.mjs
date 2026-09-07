// SECOND INSTRUMENT (DOM interrogation) for any text-on-text finding from the face gate: names each element in a reported pair, its rect, display, content-visibility, and whether it sits in a closed <details>; writes a picture. Usage: node apps/decentralized-cloud/scripts/overlap-diag.mjs (serves dist/ on 4291).
// VERIFIER DIAGNOSTIC — not a gate. Confirm-or-refute the catalog text-on-text finding.
//
// The face gate reports painted-text overlap on catalog at ALL SEVEN widths, with pairs
// like "aws · no source" over "column height is on a sq". Two things make that suspect
// before it is believed:
//
//   1. It is width-INDEPENDENT. A real reflow collision is a function of width; this one
//      reads identically at 1920 and at 390, which is what an instrument artifact looks
//      like and what a layout defect almost never looks like.
//   2. Every left-hand string in the pairs — "aws · no source", "decentralized.cloud ·
//      no", "managed_capacity · no so" — is a <li> inside a CLOSED <details class=
//      "rt-losers">. Those lines are not on the screen at all unless a reader opens the
//      disclosure.
//
// So this asks the page directly: for each element in a reported pair, what is its rect,
// its computed display/content-visibility, and does it sit inside a closed <details>?
// It also writes a screenshot, because the standing rule here is that numbers do not see
// pictures and a collision claim that has never been looked at is half a claim.
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = process.env.IOI_DIAG_OUT || "/tmp";
const PORT = Number(process.env.IOI_DIAG_PORT || 4291);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
  env: { ...process.env, IOI_DC_PORT: String(PORT), IOI_DC_DIST: path.join(APP, "dist") },
  stdio: ["ignore", "pipe", "pipe"],
});
let booted = false;
server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
// Condition, not clock — the same lesson the gate just learned twice.
for (let i = 0; i < 600 && !booted; i++) await sleep(100);
if (!booted) {
  console.log("DIAGNOSTIC VOID — the face server never started; nothing was measured.");
  server.kill("SIGTERM");
  process.exit(1);
}

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});

for (const w of [1920, 390]) {
  const page = await browser.newPage({ viewport: { width: w, height: 1000 }, deviceScaleFactor: 2 });
  await page.goto(`http://127.0.0.1:${PORT}/#/catalog`, { waitUntil: "domcontentloaded" });
  // The funnel columns are read-backed; give the read its stated time rather than
  // photographing a loading page, which has manufactured findings here before.
  await page.waitForFunction(() => !document.body.innerText.includes("asking the daemon"), { timeout: 60_000 })
    .catch(() => console.log(`  (${w}: the read had not landed in 60s — measured mid-read, say so)`));

  const report = await page.evaluate(() => {
    const pathOf = (el) => {
      const bits = [];
      for (let e = el; e && e.tagName !== "BODY"; e = e.parentElement) {
        bits.unshift(e.tagName.toLowerCase() + (e.className && typeof e.className === "string"
          ? "." + e.className.trim().split(/\s+/).join(".") : ""));
      }
      return bits.slice(-4).join(" > ");
    };
    const painted = (el) => {
      const cs = getComputedStyle(el);
      const escapes = cs.overflowX === "visible" ? Math.max(0, el.scrollWidth - el.clientWidth) : 0;
      const dir = cs.direction === "rtl" ? -1 : 1;
      return [...el.getClientRects()].filter((r) => r.width > 1 && r.height > 1).map((r) => ({
        left: dir > 0 ? r.left : r.left - escapes,
        right: dir > 0 ? r.right + escapes : r.right,
        top: r.top, bottom: r.bottom, escapes,
      }));
    };
    const closedDetails = (el) => {
      for (let e = el; e; e = e.parentElement) {
        if (e.tagName === "DETAILS" && !e.open) return pathOf(e);
      }
      return null;
    };
    const leaves = [];
    for (const el of document.querySelectorAll("body *")) {
      if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.opacity === "0") continue;
      const rects = painted(el);
      if (rects.length) leaves.push({ el, rects, text: (el.textContent || "").trim().slice(0, 24) });
    }
    const out = [];
    for (let i = 0; i < leaves.length; i++) for (let j = i + 1; j < leaves.length; j++) {
      const a = leaves[i], b = leaves[j];
      if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
      for (const ra of a.rects) for (const rb of b.rects) {
        const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
        const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
        if (ox > 3 && oy > 3) {
          const describe = (leaf, r) => ({
            text: leaf.text,
            where: pathOf(leaf.el),
            rect: [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)],
            // The two questions that separate an artifact from a defect.
            escapes: Math.round(r.escapes),
            display: getComputedStyle(leaf.el).display,
            contentVisibility: getComputedStyle(leaf.el).contentVisibility,
            insideClosedDetails: closedDetails(leaf.el),
          });
          out.push({ overlapPx: [Math.round(ox), Math.round(oy)], a: describe(a, ra), b: describe(b, rb) });
        }
      }
    }
    return { leaves: leaves.length, overlaps: out.slice(0, 6), total: out.length };
  });

  console.log(`\n═══ catalog @ ${w}px — ${report.leaves} text leaves, ${report.total} overlapping pairs`);
  for (const o of report.overlaps) {
    console.log(`\n  ${o.overlapPx[0]}×${o.overlapPx[1]}px shared`);
    for (const side of ["a", "b"]) {
      const s = o[side];
      console.log(`    "${s.text}"`);
      console.log(`       ${s.where}`);
      console.log(`       rect ${s.rect.join(",")} · display ${s.display} · content-visibility ${s.contentVisibility} · ink escaping its box ${s.escapes}px`);
      console.log(`       inside a CLOSED <details>: ${s.insideClosedDetails || "no"}`);
    }
  }
  await page.screenshot({ path: path.join(OUT, `overlap-catalog-${w}.png`), fullPage: true });
  console.log(`\n  picture: ${path.join(OUT, `overlap-catalog-${w}.png`)}`);
  await page.close();
}

await browser.close();
server.kill("SIGTERM");
