#!/usr/bin/env node
// Pipeline INTERACTION-FIDELITY verifier (#66) — proves the workspace matches the reference's
// interaction breadth over real daemon truth:
//   1. CONTROL MATRIX — the checked-in census (control-matrix.mjs) joins 1:1 with the recorded
//      reference atlas census: no reference control silently omitted, none invented, every entry
//      one of exactly four outcomes, every disabled control carrying its reason.
//   2. EVERY CONTROL ACCOUNTED — on the rendered page, every chrome control is a real link, a
//      live client control, or disabled with data-ioi-disabled-reason. No silent inert controls.
//   3. GRAPH GRAMMAR — SVG nodes (200x60, category title bars matching the legend) and TYPED
//      edges (every edge names the justifying cross-record ref; no ref → no edge).
//   4. LIVE BEHAVIOR — zoom/pan/fit mutate the viewBox; keyboard navigation; tray/legend collapse
//      persist via URL and survive reload; sub-tabs; filters; context menu; selection keeps the
//      outputs panel; embed=1 survives every interaction lane.
//   5. PER-STATE VISUAL COMPARISON — replays the SHARED state atlas (pipeline-reference-atlas.mjs)
//      against the live reference AND /__ioi/pipeline at 1440x900 + 1920x1080, diffing the
//      certified chrome islands per state with ONLY daemon/session values masked.
//   6. CLASSIFICATION — pipeline is interaction_parity_state=atlas_verified, operational_state
//      stays "inspect" (Build remains the governed ladder, #67), certs byte-identical.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-pipeline-interaction.mjs
import { execSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, INTERACTION_PARITY_STATES } from "./surface-registry.mjs";
import { CONTROL_MATRIX, CONTROL_OUTCOMES } from "../surfaces/pipeline/control-matrix.mjs";
import { ATLAS_STATES, ATLAS_CONTROLS, REFERENCE_URL } from "./pipeline-reference-atlas.mjs";
import { SURFACE_SHELL, resolveShellRects } from "./harness-reference-pixel-parity.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", ".artifacts", "pipeline-interaction");
// Interaction-parity bar: DILATED is the structural gate (1px dilation collapses AA noise, so
// 2.5% means real chrome divergence); RAW runs looser than the at-rest cert (3.0) because atlas
// states intentionally INSERT chrome (the Preview tab) whose downstream x-shifts count every
// anti-aliased glyph edge as raw diff without structural meaning. The frozen shell cert (1.25/3.0)
// is untouched — this bar governs interaction states only.
const STATE_THRESHOLDS = { dilated_pct_max: 2.5, raw_pct_max: 8.0 };

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

function resolveDataMasks(vw, vh) {
  return SURFACE_SHELL.pipeline.data.ref.map((m) => {
    let { x, y, w, h } = m.rect;
    if (m.anchor === "right") x = vw - x;
    else if (m.anchor === "bottom") y = vh - y;
    else if (m.anchor === "bottomright") { x = vw - x; y = vh - y; }
    return { left: x - 3, top: y - 3, w: w + 6, h: h + 6 };
  });
}

async function compareRegions(browser, refPng, ioiPng, rects, masks, vw) {
  const pg = await browser.newPage();
  try {
    return await pg.evaluate(async ({ refB64, ioiB64, rects, masks, vw }) => {
      const load = (b64) => new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = rej; im.src = "data:image/png;base64," + b64; });
      const [ri, ii] = await Promise.all([load(refB64), load(ioiB64)]);
      if (ri.width !== ii.width || ri.height !== ii.height) return { dims_match: false };
      const W = ri.width, H = ri.height;
      const cv = (im) => { const c = document.createElement("canvas"); c.width = W; c.height = H; const g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(im, 0, 0); return g.getImageData(0, 0, W, H).data; };
      const A = cv(ri), B = cv(ii);
      const s = W / vw;
      const inR = (rs, x, y) => { for (const r of rs) if (x >= r.left * s && x < (r.left + r.w) * s && y >= r.top * s && y < (r.top + r.h) * s) return true; return false; };
      const dist = (i) => { const dr = A[i] - B[i], dg = A[i + 1] - B[i + 1], db = A[i + 2] - B[i + 2]; return Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255; };
      const diffAt = (x, y) => dist((y * W + x) * 4) > 0.1;
      const near = (x, y) => { // 1px-dilated: any neighbor pair within threshold?
        for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
          const nx = x + dx, ny = y + dy;
          if (nx < 0 || ny < 0 || nx >= W || ny >= H) continue;
          const i = (y * W + x) * 4, j = (ny * W + nx) * 4;
          const dr = A[i] - B[j], dg = A[i + 1] - B[j + 1], db = A[i + 2] - B[j + 2];
          if (Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255 <= 0.1) return true;
          const dr2 = A[j] - B[i], dg2 = A[j + 1] - B[i + 1], db2 = A[j + 2] - B[i + 2];
          if (Math.sqrt(0.299 * dr2 * dr2 + 0.587 * dg2 * dg2 + 0.114 * db2 * db2) / 255 <= 0.1) return true;
        }
        return false;
      };
      let compared = 0, raw = 0, dilated = 0;
      for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
        if (!inR(rects, x, y) || inR(masks, x, y)) continue;
        compared++;
        if (diffAt(x, y)) { raw++; if (!near(x, y)) dilated++; }
      }
      return { dims_match: true, compared, raw_pct: compared ? +(100 * raw / compared).toFixed(3) : 0, dilated_pct: compared ? +(100 * dilated / compared).toFixed(3) : 0 };
    }, { refB64: refPng.toString("base64"), ioiB64: ioiPng.toString("base64"), rects, masks, vw });
  } finally { await pg.close(); }
}

async function run() {
  // 1. Control matrix ↔ atlas census join.
  const mIds = new Set(CONTROL_MATRIX.map((c) => c.id));
  const aIds = new Set(ATLAS_CONTROLS);
  ok("every atlas-recorded reference control appears in the control matrix (nothing silently omitted)", ATLAS_CONTROLS.every((id) => mIds.has(id)), ATLAS_CONTROLS.filter((id) => !mIds.has(id)).join(",") || "1:1");
  ok("every matrix entry is atlas-backed (nothing invented)", CONTROL_MATRIX.every((c) => aIds.has(c.id)), CONTROL_MATRIX.filter((c) => !aIds.has(c.id)).map((c) => c.id).join(",") || "1:1");
  ok("every matrix entry carries exactly one of the four outcomes", CONTROL_MATRIX.every((c) => CONTROL_OUTCOMES.includes(c.outcome)), `${CONTROL_MATRIX.length} controls`);
  ok("every disabled/unsupported control names its reason; every implemented one names its binding", CONTROL_MATRIX.every((c) => (c.outcome === "disabled_reason" || c.outcome === "unsupported" ? !!c.reason : !!c.binding)));
  const counts = CONTROL_OUTCOMES.map((o) => `${o}:${CONTROL_MATRIX.filter((c) => c.outcome === o).length}`).join(" ");
  ok("matrix census is substantial (≥70 reference controls accounted)", CONTROL_MATRIX.length >= 70, counts);

  // 2+3. Static DOM: bare route (certified default) + interaction states.
  const bare = await page(`${SERVE}/__ioi/pipeline`);
  const oid = (bare.text.match(/ontology=(ont_[a-f0-9]+)/) || [])[1] || "";
  const B = `${SERVE}/__ioi/pipeline?ontology=${oid}`;
  ok("bare route renders the SVG graph with 7 ladder nodes", bare.status === 200 && bare.text.includes('id="pb-graph"') && new Set([...bare.text.matchAll(/data-node="([a-z]+)"/g)].map((m) => m[1])).size === 7);
  const edgeMatches = [...bare.text.matchAll(/<path class="pb-edge" data-edge="([a-z]+:[a-z]+)"[^>]*>[\s\S]*?<title>typed edge — ([^=]+) = ([^<]+)<\/title>/g)];
  ok("every edge is TYPED PROOF — named justifying field + real ref, ≥8 edges on the built fixture", edgeMatches.length >= 8 && edgeMatches.every((m) => m[2].trim() && m[3].trim()), `${edgeMatches.length} edges`);
  ok("bare route: 3 tray tabs (Preview absent without selection), Selection preview active", (bare.text.match(/class="pb-tab[ "]/g) || []).length === 3 && !bare.text.includes('data-traytab="preview"') && /class="pb-tab on"[^>]*data-traytab="selection"/.test(bare.text));
  ok("bare route: NO node inspector, right title is Pipeline outputs (the certified capture state)", !bare.text.includes('id="pb-inspector"') && bare.text.includes('pb-righttitle">Pipeline outputs'));
  ok("node categories join the legend 1:1 (title-bar fills = legend chip colors)", ["#8f99a8", "#238551", "#d1980b", "#147eb3"].every((c) => bare.text.includes(`fill="${c}"`) && bare.text.includes(`background:${c}`)));

  const nodeSel = await page(`${B}&node=transform`);
  ok("node selection: selection ring on the SVG node, node detail IN THE TRAY (#pb-inspector), sub-tabs About/Fields/Receipts + disabled Schedules", /a class="pb-node[^"]*pb-nsel"[^>]*data-node="transform"/.test(nodeSel.text) && nodeSel.text.includes('id="pb-inspector"') && nodeSel.text.includes('data-sub="about"') && nodeSel.text.includes('data-sub="fields"') && nodeSel.text.includes('data-sub="receipts"') && /pb-subtab" disabled[^>]*>Schedules/.test(nodeSel.text));
  ok("node selection KEEPS the outputs panel (the #66 contract — no panel swap)", nodeSel.text.includes('pb-righttitle">Pipeline outputs') && nodeSel.text.includes("pb-outcard"));
  ok("node selection inserts the Preview tab (reference behavior)", nodeSel.text.includes('data-traytab="preview"'));
  ok("selected node gets the reference quick-action strip + Snapshot pill, all disabled with reasons", nodeSel.text.includes("pb-quickstrip") && nodeSel.text.includes("pb-snappill") && (nodeSel.text.match(/pb-qbtn[^>]*data-ioi-disabled-reason/g) || []).length >= 8);

  const warn = await page(`${B}&tab=warnings`);
  ok("warnings tab renders REAL ladder warnings with Go-to-node links", /Pipeline warnings — real ladder truth \(\d+\)/.test(warn.text) && (warn.text.match(/Go to node/g) || []).length >= 1);
  const sugg = await page(`${B}&tab=suggestions`);
  ok("suggestions tab is functional with the honest named gap (no fabricated suggestions)", sugg.text.includes("pb-sugbanner") && sugg.text.includes("no suggestion authority"));
  const prev = await page(`${B}&node=materialized&tab=preview`);
  ok("preview tab renders the REAL materialized rows + provenance refs", prev.text.includes(">L-1<") && prev.text.includes("materializing-run://"));
  const search = await page(`${B}&panel=search`);
  ok("panel=search: right panel becomes the real record census (every row a node link)", search.text.includes('pb-righttitle">Search pipeline') && (search.text.match(/class="pb-srow"/g) || []).length >= 5);
  const tree = await page(`${B}&panel=tree`);
  ok("panel=tree: the real ladder-record file tree, missing rungs honest", tree.text.includes('pb-righttitle">Pipeline file tree') && (tree.text.match(/pb-treegrp/g) || []).length >= 7);
  const outSel = await page(`${B}&output=${(bare.text.match(/data-output="([^"]+)"/) || [])[1] || "none"}`);
  ok("output selection: card selected (aria-current) + projection detail in the tray", outSel.text.includes("pb-outsel") && outSel.text.includes('id="pb-tray-output"'));
  const bogusTab = await page(`${B}&tab=bogus`);
  const bogusPanel = await page(`${B}&panel=bogus`);
  const previewNoSel = await page(`${B}&tab=preview`);
  ok("unknown tab / unknown panel / preview-without-selection all fail CLOSED with visible notes", bogusTab.text.includes("Unknown tray tab") && bogusPanel.text.includes("Unknown panel") && previewNoSel.text.includes("exists only with a selection"));

  // 2. Every-control-accounted sweep: in the chrome regions, every <button> is live-or-disabled
  // -with-reason and every <a> has a real href.
  const chrome = nodeSel.text;
  const buttons = [...chrome.matchAll(/<button\b[^>]*>/g)].map((m) => m[0]);
  const silent = buttons.filter((b) => !/disabled/.test(b) ? !/id="pb-[a-z-]+"|class="pb-subtab|class="pb-legeye"/.test(b) : !/data-ioi-disabled-reason=|title="/.test(b));
  ok("every rendered button is a live client control (id) XOR disabled with its reason — no silent inert controls", silent.length === 0, silent.slice(0, 2).join(" ").slice(0, 160) || `${buttons.length} buttons accounted`);
  const emptyHrefs = [...chrome.matchAll(/<a\b[^>]*href="(#?)"[^>]*>/g)].filter((m) => m[1] === "");
  ok("no blank-href anchors in the workspace", emptyHrefs.length === 0);

  // Header overlap fix is capture-invisible and live below 1440.
  ok("1140px header fix ships as a max-width:1439 rule (bare 1440/1920 captures mathematically unaffected)", bare.text.includes("@media(max-width:1439px)") && /max-width:1439px[^}]*\{[^}]*\.pb-hmid\{width:auto;right:250px/.test(bare.text.replace(/\n/g, "")));

  // 6. Classification + certs.
  const pl = SURFACES.find((s) => s.slug === "pipeline");
  ok("registry: pipeline interaction_parity_state=atlas_verified, operational_state stays inspect (Build waits for #67), vocab valid", pl.interaction_parity_state === "atlas_verified" && pl.operational_state === "inspect" && SURFACES.every((s) => INTERACTION_PARITY_STATES.includes(s.interaction_parity_state)));
  const dirty = execSync("git status --porcelain -- pixel-certifications", { cwd: join(HERE, ".."), encoding: "utf8" }).trim();
  ok("pixel-certification artifacts byte-identical", dirty === "", dirty || "clean");

  // 4+5. Live behavior + per-state visual comparison.
  {
    const { chromium } = await import("playwright");
    const browser = await chromium.launch();
    mkdirSync(OUT, { recursive: true });
    try {
      // ---- 4. Live behavior on IOI.
      const pg = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      await pg.goto(`${B}&node=transform&embed=1`, { waitUntil: "networkidle" });
      const vb0 = await pg.getAttribute("#pb-graph", "viewBox");
      await pg.click("#pb-zin");
      const vbIn = await pg.getAttribute("#pb-graph", "viewBox");
      await pg.click("#pb-zfit");
      const vbFit = await pg.getAttribute("#pb-graph", "viewBox");
      ok("zoom in mutates the viewBox; zoom-to-fit restores it", vbIn !== vb0 && vbFit === vb0, `${vb0} → ${vbIn}`);
      const g = await pg.locator("#pb-graph").boundingBox();
      await pg.mouse.move(g.x + g.width / 2, g.y + 40);
      await pg.mouse.down(); await pg.mouse.move(g.x + g.width / 2 - 120, g.y + 80, { steps: 4 }); await pg.mouse.up();
      const vbPan = await pg.getAttribute("#pb-graph", "viewBox");
      ok("canvas drag pans the graph (pan mode is the live default)", vbPan !== vbFit, vbPan);
      await pg.focus("#pb-graph");
      await pg.keyboard.press("Home");
      await pg.keyboard.press("ArrowRight");
      const focused = await pg.evaluate(() => document.activeElement && document.activeElement.getAttribute && document.activeElement.getAttribute("data-node"));
      ok("keyboard navigation moves node focus (Home → ArrowRight lands on the second node)", focused === "mapping", focused);
      await pg.keyboard.press("Enter");
      await pg.waitForURL(/node=mapping/, { timeout: 8000 }).catch(() => {});
      ok("Enter activates the focused node — URL selection updates AND embed=1 survives client navigation", pg.url().includes("node=mapping") && pg.url().includes("embed=1"), pg.url());
      // tray collapse → replaceState → reload persistence
      await pg.click("#pb-tray-toggle");
      ok("tray collapse persists to the URL via replaceState (tray=0, embed intact)", pg.url().includes("tray=0") && pg.url().includes("embed=1"), pg.url());
      await pg.reload({ waitUntil: "networkidle" });
      ok("reload preserves the collapsed tray (server renders ?tray=0)", await pg.locator(".pb-tray.pb-collapsed").count() === 1);
      await pg.click("#pb-tray-toggle"); // restore
      // legend eye → hide param → reload persistence
      await pg.click('.pb-legeye[data-cat="clean"]');
      ok("legend eye hides the category live + persists (?hide=clean)", pg.url().includes("hide=clean") && await pg.locator('a.pb-node[data-category="clean"]').first().isHidden(), pg.url());
      await pg.reload({ waitUntil: "networkidle" });
      ok("reload preserves hidden categories (server renders ?hide=)", await pg.locator('a.pb-node[data-category="clean"]').first().isHidden() && await pg.locator('.pb-legrow.off').count() >= 1);
      await pg.click('.pb-legeye[data-cat="clean"]'); // restore the category before the context-menu step targets a clean node
      ok("legend eye toggles back (category restored, hide= dropped)", !pg.url().includes("hide=clean") && await pg.locator('a.pb-node[data-category="clean"]').first().isVisible());
      // sub-tabs (client view toggle)
      await pg.click('.pb-subtab[data-sub="receipts"]');
      ok("node sub-tabs toggle panes client-side (Receipts shows the real chain)", await pg.locator('.pb-subpane[data-sub="receipts"]').isVisible() && await pg.locator('.pb-subpane[data-sub="about"]').isHidden());
      // outputs search filter
      await pg.fill("#pb-outsearch", "zzz-no-match");
      ok("outputs search filters cards client-side", await pg.locator(".pb-outcard").first().isHidden());
      await pg.fill("#pb-outsearch", "");
      // context menu
      await pg.click("#pb-zfit");
      const nodeBox = await pg.locator('a.pb-node[data-node="mapping"]').boundingBox();
      await pg.mouse.click(nodeBox.x + nodeBox.width / 2, nodeBox.y + nodeBox.height / 2, { button: "right" });
      ok("node context menu opens with Open + Copy record ref live and authoring items disabled with reasons", await pg.locator("#pb-ctxmenu").isVisible() && await pg.locator("#pb-ctx-open").isEnabled() && await pg.locator('#pb-ctxmenu button[disabled][data-ioi-disabled-reason]').count() === 5);
      await pg.click("#pb-ctx-open");
      await pg.waitForLoadState("networkidle");
      ok("context-menu Open navigates via the pre-rendered href (embed preserved)", pg.url().includes("node=mapping") && pg.url().includes("embed=1"));
      // panel swap via the icon rail, embedded
      await pg.click('a.pb-stripico[data-panel="search"]');
      await pg.waitForLoadState("networkidle");
      ok("icon-rail panel swap stays embedded and renders the search census", pg.url().includes("panel=search") && pg.url().includes("embed=1") && await pg.locator(".pb-srow").first().isVisible());
      // fixture-agnostic term: filter by the FIRST census row's record id (verifier runs mint new
      // fixture ontologies, so a literal name would go stale).
      const term = ((await pg.locator(".pb-srow").first().getAttribute("data-search")) || "").split(" ")[1] || "";
      await pg.fill("#pb-psearch", term);
      const visRows = await pg.locator(".pb-srow:visible").count();
      const total = await pg.locator(".pb-srow").count();
      ok("pipeline search filters records as-you-type with a live match count", term.length > 0 && visRows >= 1 && visRows < total && (await pg.locator("#pb-srcount").textContent()).includes("match"), `${visRows}/${total} visible for '${term}'`);
      await pg.close();

      // ---- 5. Per-state visual comparison (the atlas, both certified viewports).
      for (const vp of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
        const key = `${vp.width}x${vp.height}`;
        const templates = (vp.width === 1920 && SURFACE_SHELL.pipeline.rects_by_viewport["1920x1080"]) || SURFACE_SHELL.pipeline.rects;
        const allRects = resolveShellRects(templates, vp.width, vp.height);
        const dataMasks = resolveDataMasks(vp.width, vp.height);
        for (const st of ATLAS_STATES) {
          const rects = allRects.filter((r) => st.compareIslands.includes(r.key));
          const masks = [...dataMasks, ...st.extraMasks(vp.width, vp.height)];
          let refShot = null, ioiShot = null, refErr = "";
          const rp = await browser.newPage({ viewport: vp });
          try {
            await rp.goto(REFERENCE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
            await st.ref(rp);
            refShot = await rp.screenshot();
          } catch (e) { refErr = String(e.message || e).slice(0, 120); } finally { await rp.close(); }
          const ip = await browser.newPage({ viewport: vp });
          let ioiErr = "";
          try {
            await ip.goto(`${B}${st.ioiQuery}`, { waitUntil: "networkidle", timeout: 30000 });
            if (st.ioiDrive) await st.ioiDrive(ip);
            ioiShot = await ip.screenshot();
          } catch (e) { ioiErr = String(e.message || e).slice(0, 120); } finally { await ip.close(); }
          if (!refShot || !ioiShot) { ok(`state ${st.key} @ ${key}: both sides captured`, false, refErr || ioiErr); continue; }
          const { writeFileSync } = await import("node:fs");
          writeFileSync(join(OUT, `${st.key}-${key}-ref.png`), refShot);
          writeFileSync(join(OUT, `${st.key}-${key}-ioi.png`), ioiShot);
          const cmp = await compareRegions(browser, refShot, ioiShot, rects, masks, vp.width);
          ok(`state ${st.key} @ ${key}: certified-chrome diff within the interaction bar (dilated ≤${STATE_THRESHOLDS.dilated_pct_max}% raw ≤${STATE_THRESHOLDS.raw_pct_max}%, only daemon/session values masked)`,
            cmp.dims_match && cmp.dilated_pct <= STATE_THRESHOLDS.dilated_pct_max && cmp.raw_pct <= STATE_THRESHOLDS.raw_pct_max,
            `dilated ${cmp.dilated_pct}% raw ${cmp.raw_pct}% over ${cmp.compared}px [islands: ${st.compareIslands.join(",")}]`);
        }
      }
    } finally {
      await browser.close();
    }
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("pipeline interaction-fidelity: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
