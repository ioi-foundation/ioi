// PROVES: the face gate's collision probe catches a visible text overlap, ignores the same overlap behind a closed <details>, and catches it again once opened — run after any edit to that probe. Usage: node apps/decentralized-cloud/scripts/collision-mutant.mjs (serves dist/ on 4293).
// POSITIVE CONTROL for the collision probe's closed-disclosure fix.
//
// The probe now excludes elements that are laid out but not painted. That change made
// seven false findings disappear — and an exclusion that makes findings disappear is
// exactly the kind of fix that can quietly make a probe stop working. Its assertions
// went green at every width, but "no collisions reported" is what a correct probe and a
// blind probe both look like.
//
// So this plants collisions and checks WHICH ONES the probe reports. The useful part of
// a mutation test is where it does NOT fail:
//
//   MUTANT 1 — two VISIBLE text elements forced on top of each other. Must be CAUGHT.
//             If this is missed, the fix blinded the probe and must be reverted.
//   MUTANT 2 — an element inside a CLOSED <details> forced over visible text. Must be
//             MISSED, because a reader cannot see it. This is the false finding that
//             cost three runs.
//   MUTANT 3 — the same disclosure OPENED, with the same overlap. Must be CAUGHT: once
//             a reader opens it, the collision is real, and an exclusion that keys on
//             the element rather than on its state would wrongly stay silent.
//
// Nothing here touches src/ — the mutations are injected into the live page as style
// and property changes, so the designer's tree is not modified to test my instrument.
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = Number(process.env.IOI_DIAG_PORT || 4293);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
  env: { ...process.env, IOI_DC_PORT: String(PORT), IOI_DC_DIST: path.join(APP, "dist") },
  stdio: ["ignore", "pipe", "pipe"],
});
let booted = false;
server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
for (let i = 0; i < 600 && !booted; i++) await sleep(100);
if (!booted) {
  console.log("MUTATION RUN VOID — the face server never started; no mutant was tested.");
  server.kill("SIGTERM");
  process.exit(1);
}

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 390, height: 1000 } });
await page.goto(`http://127.0.0.1:${PORT}/#/catalog`, { waitUntil: "domcontentloaded" });
await page.waitForSelector("details.rt-losers", { timeout: 120_000 }).catch(() => {});

// THE PROBE'S OWN LOGIC, verbatim in shape, so this tests the gate's rule and not a
// paraphrase of it. A positive control against a re-implementation proves nothing about
// the instrument that actually ships.
const probe = () => {
  const painted = (el) => {
    const cs = getComputedStyle(el);
    const escapes = cs.overflowX === "visible" ? Math.max(0, el.scrollWidth - el.clientWidth) : 0;
    const dir = cs.direction === "rtl" ? -1 : 1;
    return [...el.getClientRects()].filter((r) => r.width > 1 && r.height > 1).map((r) => ({
      left: dir > 0 ? r.left : r.left - escapes,
      right: dir > 0 ? r.right + escapes : r.right,
      top: r.top, bottom: r.bottom,
    }));
  };
  const unpainted = (el) => {
    for (let e = el; e && e !== document.body; e = e.parentElement) {
      if (e.tagName === "DETAILS" && !e.open) return true;
      if (getComputedStyle(e).contentVisibility === "hidden") return true;
    }
    return false;
  };
  let skipped = 0;
  const leaves = [];
  for (const el of document.querySelectorAll("body *")) {
    if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === "hidden" || cs.opacity === "0") continue;
    if (unpainted(el)) { skipped += 1; continue; }
    const rects = painted(el);
    if (rects.length) leaves.push({ el, rects, text: (el.textContent || "").trim().slice(0, 30) });
  }
  const over = [];
  for (let i = 0; i < leaves.length; i++) for (let j = i + 1; j < leaves.length; j++) {
    const a = leaves[i], b = leaves[j];
    if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
    for (const ra of a.rects) for (const rb of b.rects) {
      const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
      const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (ox > 3 && oy > 3) over.push(`"${a.text}" over "${b.text}"`);
    }
  }
  return { skipped, leaves: leaves.length, over: [...new Set(over)] };
};

const MARK = "MUTANT-PLANTED-STRING";

const baseline = await page.evaluate(probe);
console.log(`baseline — ${baseline.leaves} leaves, ${baseline.skipped} skipped, ${baseline.over.length} collisions`);

// ── MUTANT 1: two visible elements, forced to overlap. MUST BE CAUGHT. ──────
const m1 = await page.evaluate((mark) => {
  const host = document.querySelector(".rt-caption") || document.querySelector("p, div");
  const planted = document.createElement("div");
  planted.textContent = mark;
  planted.id = "mutant-visible";
  const r = host.getBoundingClientRect();
  planted.style.cssText =
    `position:absolute; left:${r.left + window.scrollX}px; top:${r.top + window.scrollY}px; ` +
    `width:${Math.max(40, r.width)}px; height:${Math.max(20, r.height)}px; font-size:14px; z-index:99;`;
  document.body.appendChild(planted);
  return host.textContent.trim().slice(0, 30);
}, MARK);
const r1 = await page.evaluate(probe);
const caught1 = r1.over.some((s) => s.includes(MARK));
console.log(`\nMUTANT 1  two VISIBLE elements overlapping (over "${m1}")`);
console.log(`  ${caught1 ? "CAUGHT" : "MISSED"} — ${caught1 ? "the probe still sees a real collision" : "THE FIX BLINDED THE PROBE; revert it"}`);
if (caught1) console.log(`  ${r1.over.filter((s) => s.includes(MARK)).slice(0, 2).join(" · ")}`);

// ── MUTANT 2: same overlap, but inside a CLOSED <details>. MUST BE MISSED. ──
await page.evaluate((mark) => {
  document.getElementById("mutant-visible")?.remove();
  const d = document.querySelector("details.rt-losers");
  const host = document.querySelector(".rt-caption");
  const planted = document.createElement("div");
  planted.textContent = mark;
  planted.id = "mutant-hidden";
  const r = host.getBoundingClientRect();
  planted.style.cssText =
    `position:absolute; left:${r.left + window.scrollX}px; top:${r.top + window.scrollY}px; ` +
    `width:${Math.max(40, r.width)}px; height:${Math.max(20, r.height)}px; font-size:14px; z-index:99;`;
  d.open = false;
  d.appendChild(planted);
}, MARK);
const r2 = await page.evaluate(probe);
const caught2 = r2.over.some((s) => s.includes(MARK));
console.log(`\nMUTANT 2  the same overlap, inside a CLOSED <details>`);
console.log(`  ${caught2 ? "CAUGHT" : "MISSED"} — ${caught2 ? "STILL REPORTING TEXT NO READER CAN SEE; the fix did not take" : "correct: a reader cannot see it, so it is not a finding"}`);
console.log(`  ${r2.skipped} elements skipped as laid-out-but-unpainted`);

// ── MUTANT 3: the same disclosure OPENED. MUST BE CAUGHT. ──────────────────
await page.evaluate(() => { document.querySelector("details.rt-losers").open = true; });
const r3 = await page.evaluate(probe);
const caught3 = r3.over.some((s) => s.includes(MARK));
console.log(`\nMUTANT 3  the same element, disclosure now OPEN`);
console.log(`  ${caught3 ? "CAUGHT" : "MISSED"} — ${caught3 ? "correct: the exclusion keys on the disclosure's STATE, not on the element" : "THE EXCLUSION IS PERMANENT; a collision a reader can see is being suppressed"}`);

const verdict = caught1 && !caught2 && caught3;
console.log(`\n${verdict ? "ALL THREE MUTANTS BEHAVED" : "MUTATION FAILURE"} — caught the visible one: ${caught1}; ` +
  `missed the hidden one: ${!caught2}; caught it again once opened: ${caught3}`);

await browser.close();
server.kill("SIGTERM");
process.exit(verdict ? 0 : 1);
