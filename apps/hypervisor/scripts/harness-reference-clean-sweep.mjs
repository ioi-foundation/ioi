#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #44 — ESTATE REFERENCE DATA-CLEAN SWEEP (infrastructure only; no ports,
// no promotions, no parity_class changes, no shell-pixel certification changes).
//
// The authoritative estate-wide answer to: "which references are actually clean
// enough to port/certify next?" Sweeps ALL 39 seeds with real Playwright
// renders over the LOCAL lanes only:
//   proxy lane  — SERVE /__apps/<slug>          (token-injected estate proxy)
//   origin lane — MIRROR <capture_base>          (the capture's own origin path;
//                 the lane that unblocked pipeline in #38/#39)
// plus the per-seed reference_url_override when the matrix carries one.
//
// Classification (one state per seed, evidence-backed, fail-first precedence):
//   errored_reference · missing_chunk · cors_origin_mismatch · blank_reference
//   · modal_blocked · data_failed · needs_backend_reharvest
//   · needs_origin_alignment · data_clean · shell_clean_only · unknown_blocked
//
// Evidence per seed: shell regions (geometry-gated, same predicates as the
// visual harness) · observed landmarks · data evidence (table rows / graph
// nodes / cards / list items / meaningful text) · console+page errors ·
// failed/4xx network requests (missing chunk hashes, API-lane failures) ·
// CORS/origin signals · capture-store fs facts (file count, deep routes) ·
// screenshot per lane. Screenshots are never the sole evidence — every state
// is derived from DOM/text/network signals; the png is corroboration.
//
// Outputs:
//   .artifacts/reference-clean-sweep/result.json        (full evidence)
//   .artifacts/reference-clean-sweep/contact-sheet.html (all seeds, both lanes)
//   .artifacts/reference-clean-sweep/<slug>-<lane>.png  (screenshots)
//   .artifacts/reference-clean-sweep/<slug>-network.json(per-seed request log)
//   reference-clean-sweep.json (COMMITTED compact evidence — the matrix's
//   reference_clean_* source of truth; parity_class is never touched)
//
// Controls: schema / approvals / pipeline must classify data_clean (they are
// certified surfaces over VALID references — if a control misclassifies, the
// sweep's heuristics are wrong, not the reference). An errored reference must
// never classify clean even when the global rail renders.
// ---------------------------------------------------------------------------
import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REFERENCE_PRE_CAPTURE, ERROR_PAGE_RE } from "./harness-reference-parity.mjs";

// The sweep reads a WIDER error vocabulary than the visual harness (audit pass:
// permission-denied captures, invalid-resource-id proxy routes, context-path
// failures all masqueraded as blank/clean).
const SWEEP_ERROR_RE = new RegExp(ERROR_PAGE_RE.source + "|don'?t have permission|no permission|not authorized|invalid resource identifier|is not a dataset|context path not found|couldn'?t find this path", "i");

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const repoRoot = path.resolve(appRoot, "..", "..");
const SERVE = process.env.IOI_SERVE_URL || "http://127.0.0.1:4173";
const MIRROR = process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225";
// The capture ORIGIN the seed documents hardcode (localhost, NOT 127.0.0.1 — the
// hostname mismatch alone manufactures CORS noise; pipeline's #39 override uses
// localhost for exactly this reason). Origin-lane probes run here.
const CAPTURE_ORIGIN = process.env.IOI_SWEEP_ORIGIN || MIRROR.replace("127.0.0.1", "localhost");
const OUT = process.env.IOI_SWEEP_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "reference-clean-sweep");
const COMMITTED = path.join(appRoot, "reference-clean-sweep.json");
const MIRROR_PUBLIC = path.join(repoRoot, "internal-docs", "reverse-engineering", "palantir", "public");
const ONLY = (process.env.IOI_SWEEP_SEEDS || "").split(",").map((s) => s.trim()).filter(Boolean);
const CONCURRENCY = Number(process.env.IOI_SWEEP_CONCURRENCY || 4);

export const CLEAN_STATES = [
  "data_clean", "shell_clean_only", "blank_reference", "errored_reference",
  "cors_origin_mismatch", "missing_chunk", "modal_blocked", "data_failed",
  "needs_backend_reharvest", "needs_origin_alignment", "unknown_blocked",
];

// The reference chrome region predicates — the SAME geometry discipline as the
// visual harness (selector match alone never counts; layout must agree).
const REGION_SELECTORS = {
  rail: '[class*="rail"],[class*="sidebar"],[class*="side-nav"],nav,aside',
  header: 'header,[class*="header"],[class*="navbar"],[class*="topbar"],[class*="app-bar"]',
  toolbar: '[role="toolbar"],[class*="toolbar"],[class*="tool-bar"],[class*="actions-bar"]',
  body: 'main,[class*="content"],[class*="canvas"],[class*="workspace"],[class*="body"]',
  right: '[class*="right-panel"],[class*="rightPanel"],[class*="side-panel"],[class*="inspector"],[class*="details-panel"]',
  tray: 'footer,[class*="tray"],[class*="bottom-panel"],[class*="footer"]',
};

// Data-lane API families the capture serves (mirrors the serve proxy's list) —
// a 4xx/5xx on these is a DATA-LANE failure, not a chrome asset problem.
const API_FAMILY_RE = /\/(multipass|graphql-gateway|compass|monocle|approvals|workspace\/api|interventions|ontology-metadata|magritte-coordinator|issues|foundry-search|marketplace|object-set-service|phonograph2|language-model-service|foundry-ml|artifacts|foundry-catalog|models|build2|foundry-stemma|third-party-applications|developer-console|aip-assist|documentation|log-receiver)\//;
const CHUNK_RE = /\.(js|mjs|css)(\?|$)|content-addressable-storage/;

// Post-boot interactions (no auth/origin change — a single in-app click, like a
// user switching a status lane). Applied to EVERY lane after modal handling;
// recorded on the lane so the classification names it.
const SWEEP_INTERACTIONS = {
  incidents: { note: "clicked the 'Closed' status lane (the default Open lane is honestly empty; the capture carries 5 real closed incidents)", run: async (page) => {
    await page.getByText("Closed", { exact: true }).first().click({ timeout: 3000 });
    await page.waitForTimeout(900);
  } },
};

function seedRows() {
  const m = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  return (m.seeds || []).filter((s) => !ONLY.length || ONLY.includes(s.slug));
}

// Capture-store fs facts: how much of this seed's workspace was actually
// captured (index-only shells cannot carry deep data routes).
function captureStoreFacts(captureBase) {
  const dir = path.join(MIRROR_PUBLIC, ...(captureBase || "").split("/").filter(Boolean));
  const facts = { present: false, file_count: 0, deep_route_dirs: [], bytes: 0 };
  if (!captureBase || !existsSync(dir)) return facts;
  facts.present = true;
  const walk = (d, depth) => {
    let entries = [];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (depth === 0) facts.deep_route_dirs.push(e.name);
        if (depth < 3) walk(p, depth + 1);
      } else {
        facts.file_count += 1;
        try { facts.bytes += statSync(p).size; } catch { /* */ }
      }
    }
  };
  walk(dir, 0);
  facts.deep_route_dirs = facts.deep_route_dirs.slice(0, 12);
  return facts;
}

// ---- one lane render: full network/console/DOM evidence -------------------
async function sweepLane(browser, url, slug, laneName, preCapture, matrixLandmarks) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const net = { failed: [], http_errors: [], cross_origin_9225: 0, total: 0 };
  const consoleErrors = [], pageErrors = [];
  const pageOrigin = new URL(url).origin;
  page.on("requestfailed", (r) => {
    const f = r.failure();
    net.failed.push({ url: r.url().slice(0, 220), error: (f && f.errorText) || "", type: r.resourceType() });
  });
  page.on("response", (r) => {
    net.total += 1;
    const st = r.status();
    if (st >= 400) net.http_errors.push({ url: r.url().slice(0, 220), status: st, type: r.request().resourceType() });
  });
  page.on("request", (r) => {
    try { if (new URL(r.url()).origin !== pageOrigin && /:9225$/.test(new URL(r.url()).host)) net.cross_origin_9225 += 1; } catch { /* */ }
  });
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text().slice(0, 260)); });
  page.on("pageerror", (e) => pageErrors.push(String(e.message || e).slice(0, 260)));

  const lane = { lane: laneName, url, loaded: true, nav_error: "", evidence: null, evidence_pre_modal: null, modal: null, screenshot: "" };
  try {
    await page.emulateMedia({ reducedMotion: "reduce" }).catch(() => {});
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 });
    await page.addStyleTag({ content: "*,*::before,*::after{animation-duration:.001s !important;transition-duration:.001s !important;caret-color:transparent !important}" }).catch(() => {});
    await page.evaluate(() => Promise.race([
      document.fonts && document.fonts.ready ? document.fonts.ready.then(() => true).catch(() => true) : Promise.resolve(true),
      new Promise((r) => setTimeout(() => r(true), 3000)),
    ])).catch(() => {});
    await page.waitForTimeout(3200); // reference SPA hydrate
  } catch (e) {
    lane.loaded = false;
    const msg = String(e.message || e);
    lane.nav_error = /Download is starting/i.test(msg)
      ? "navigation triggered a content-type download — the captured app document is an empty 307 + application/octet-stream response (broken capture, cannot boot on any lane)"
      : msg.split("\n")[0].slice(0, 160);
  }

  const snapshot = async () => page.evaluate(({ sel, ERR, ML }) => {
    const VW = innerWidth, VH = innerHeight;
    const vis = (el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 24 && r.height > 24 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0" ? r : null; };
    const geom = {
      rail: (b) => b.left < VW * 0.15 && b.height > VH * 0.4,
      header: (b) => b.top < VH * 0.15 && b.width > VW * 0.5 && b.height < VH * 0.28,
      toolbar: (b) => b.top < VH * 0.4 && b.width > VW * 0.25 && b.height < VH * 0.22,
      body: (b) => b.width > VW * 0.4 && b.height > VH * 0.35,
      right: (b) => b.right > VW * 0.8 && b.height > VH * 0.3 && b.width < VW * 0.6,
      tray: (b) => b.bottom > VH * 0.8 && b.width > VW * 0.4 && b.height < VH * 0.4,
    };
    const regions = [];
    for (const [k, q] of Object.entries(sel)) {
      let hit = false;
      for (const el of document.querySelectorAll(q)) { const b = vis(el); if (b && geom[k](b)) { hit = true; break; } }
      if (hit) regions.push(k);
    }
    // data evidence — DOM signals, never pixels
    let tableRows = 0;
    for (const tb of document.querySelectorAll("table tbody")) tableRows = Math.max(tableRows, tb.querySelectorAll("tr").length);
    const ariaRows = document.querySelectorAll('[role="row"]').length;
    tableRows = Math.max(tableRows, Math.max(0, ariaRows - 1));
    const nodeEls = document.querySelectorAll('[data-node-id],[class*="node-card"],[class*="graph-node"],[class*="nodeCard"],svg [class*="node"]');
    let graphNodes = 0; for (const el of nodeEls) if (vis(el) || el.ownerSVGElement) graphNodes += 1;
    let cards = 0; for (const el of document.querySelectorAll('[class*="card"]')) { const b = vis(el); if (b && b.width > 80 && b.height > 48) cards += 1; }
    let listItems = 0; for (const el of document.querySelectorAll('li,[role="listitem"],[role="option"],[role="menuitem"]')) if (vis(el)) listItems += 1;
    // repeated-structure rows: custom-DOM lists/tables (>=4 same-class visible
    // siblings, uniform height, textual) — the approvals reference renders its
    // request list this way (co-table-rows > approvals-components__row-container).
    let repeatedRows = 0;
    for (const el of document.querySelectorAll("div,ul,ol,section")) {
      // CONTENT-AREA guard: the global rail / app sidebars are themselves uniform
      // repeated structures (8x nav rows) — chrome must never count as data.
      const pb = el.getBoundingClientRect();
      if (pb.left < VW * 0.16 && pb.width < VW * 0.5) continue;
      if (el.closest("nav,aside,[class*='sidebar'],[class*='side-nav'],[class*='rail']")) continue;
      const kids = []; for (const k of el.children) { const b = vis(k); if (b && b.width > 60) kids.push({ k, h: b.height }); }
      if (kids.length < 4) continue;
      const cls = (k) => (String(k.className || "").split(/\s+/)[0] || k.tagName);
      const first = cls(kids[0].k);
      const same = kids.filter((x) => cls(x.k) === first);
      if (same.length < 4) continue;
      const avg = same.reduce((a, c) => a + c.h, 0) / same.length;
      if (!same.every((x) => Math.abs(x.h - avg) < Math.max(8, avg * 0.35))) continue;
      const texty = same.filter((x) => ((x.k.textContent || "").trim().length > 8)).length;
      if (texty >= 3 && avg >= 18 && avg <= 160) repeatedRows = Math.max(repeatedRows, same.length);
    }
    const text = (document.body && document.body.innerText) || "";
    const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 2);
    const meaningful = lines.filter((l) => l.length >= 12).length;
    const errLine = (() => { const re = new RegExp(ERR, "i"); for (const l of lines) if (re.test(l)) return l.slice(0, 160); return ""; })();
    // landmark-ish labels: short distinct texts in nav/header/aside chrome
    const lm = new Set();
    for (const el of document.querySelectorAll("nav *,aside *,header *,[class*='sidebar'] *,[class*='rail'] *")) {
      if (el.children.length) continue;
      const t = (el.textContent || "").trim();
      if (t && t.length >= 3 && t.length <= 32) lm.add(t);
      if (lm.size >= 24) break;
    }
    const overlays = [];
    for (const el of document.querySelectorAll('[class*="overlay"],[class*="portal"],[class*="dialog"],[class*="modal"],[role="dialog"]')) {
      const b = vis(el); if (b && b.width > 200 && b.height > 120) overlays.push(((el.className && String(el.className)) || el.tagName).slice(0, 60));
    }
    let spinners = 0; for (const el of document.querySelectorAll('[class*="spinner"],[class*="loading"],[class*="skeleton"],[class*="progress"]')) if (vis(el)) spinners += 1;
    const matrixLm = ML.filter((l) => text.includes(l));
    const welcome = /welcome to |get started|getting started|create your first|no .{0,24} yet\b|there (are|is) no |no [^\n]{0,28}(found|available)\b|all [^\n]{0,24}completed|add [^\n]{0,24}to get started|learn about\b/i.test(text);
    return {
      title: document.title || "", regions, landmarks: [...lm], matrix_landmarks: matrixLm,
      data: { table_rows: tableRows, graph_nodes: graphNodes, cards, list_items: listItems, repeated_rows: repeatedRows, body_text_chars: text.length, meaningful_lines: meaningful },
      error_text: errLine, overlays, spinners, welcome_state: welcome, body_sample: text.slice(0, 600),
    };
  }, { sel: REGION_SELECTORS, ERR: SWEEP_ERROR_RE.source, ML: Array.isArray(matrixLandmarks) ? matrixLandmarks : [] }).catch((e) => ({ snapshot_error: String(e.message || e).slice(0, 120) }));

  if (lane.loaded) {
    lane.evidence_pre_modal = await snapshot();
    // Modal probe: if a blocking overlay is up, dismiss THE SAME WAY the pipeline
    // pre-capture does (Escape + hide portal layers — no auth/origin change) and
    // re-measure. The delta is the modal_blocked evidence.
    const hadOverlay = (lane.evidence_pre_modal.overlays || []).length > 0;
    if (preCapture) { try { await preCapture(page); } catch { /* best effort */ } await page.waitForTimeout(400); }
    else if (hadOverlay) {
      await page.keyboard.press("Escape").catch(() => {});
      await page.addStyleTag({ content: '.bp6-portal,.bp6-overlay,.bp6-overlay-backdrop,[class*="whats-new"],[data-portal]{display:none !important}' }).catch(() => {});
      await page.waitForTimeout(700);
    }
    const inter = SWEEP_INTERACTIONS[slug];
    if (inter) { try { await inter.run(page); lane.interaction = inter.note; } catch { /* lane may not render the control */ } }
    lane.evidence = await snapshot();
    lane.modal = {
      overlay_pre: hadOverlay,
      overlay_post: (lane.evidence.overlays || []).length > 0,
      dismissed_reveals_data: hadOverlay && dataScore(lane.evidence.data) > dataScore(lane.evidence_pre_modal.data),
    };
    const png = path.join(OUT, `${slug}-${laneName}.png`);
    try { await page.screenshot({ path: png }); lane.screenshot = path.relative(appRoot, png); } catch { /* */ }
  }
  lane.network = {
    total: net.total,
    failed: net.failed.slice(0, 24),
    http_errors: net.http_errors.slice(0, 40),
    cross_origin_9225: net.cross_origin_9225,
    chunk_404s: net.http_errors.filter((e) => CHUNK_RE.test(e.url)).slice(0, 16),
    api_failures: net.http_errors.filter((e) => API_FAMILY_RE.test(e.url)).slice(0, 24),
  };
  lane.console_errors = consoleErrors.slice(0, 20);
  lane.page_errors = pageErrors.slice(0, 10);
  lane.cors_signals = consoleErrors.filter((t) => /CORS|Cross-Origin|blocked by CORS|Access-Control-Allow/i.test(t)).slice(0, 8);
  await ctx.close();
  return lane;
}

function dataScore(d) {
  if (!d) return 0;
  return (d.table_rows >= 3 ? 3 : 0) + (d.repeated_rows >= 4 ? 3 : 0) + (d.graph_nodes >= 3 ? 3 : 0) + (d.cards >= 3 ? 2 : 0)
    + (d.list_items >= 8 ? 1 : 0) + (d.meaningful_lines >= 10 ? 1 : 0) + (d.body_text_chars >= 1200 ? 1 : 0);
}
const hasData = (d) => dataScore(d) >= 3;
// REAL data: strong signals that are not a welcome/empty landing masquerading as
// content (audit pass: quick-start pickers, doc-link cards, empty-counter chrome).
// Welcome-landing override (audit-calibrated): real user tables run 6+ repeated
// rows or ANY nonzero table rows (notepad's 2 real resources count); onboarding
// card-lists run 4-5 uniform items with zero rows (analysis/registry/devconsole).
const realData = (ev) => !!ev && hasData(ev.data)
  && !(ev.welcome_state && (ev.data.table_rows | 0) === 0 && (ev.data.repeated_rows | 0) < 6 && (ev.data.graph_nodes | 0) < 3);
const shellOk = (ev) => ev && Array.isArray(ev.regions) && ev.regions.length >= 2;
const isBlank = (ev) => !ev || ((ev.data?.body_text_chars || 0) < 60 && (ev.regions || []).length <= 1);

// ---- classification: one state, fail-first, evidence named -----------------
function classify(seed, lanes, storeFacts) {
  const proxyReal = lanes.proxy && lanes.proxy.loaded && realData(lanes.proxy.evidence) && !lanes.proxy.evidence?.error_text;
  const linesOf = (l) => (l && l.loaded && l.evidence && l.evidence.data && l.evidence.data.meaningful_lines) || 0;
  const pick = lanes.override
    || (proxyReal ? lanes.proxy : null)
    || ((lanes.origin && lanes.origin.loaded && dataScore(lanes.origin.evidence?.data) > dataScore(lanes.proxy?.evidence?.data)) ? lanes.origin : null)
    || ((lanes.origin && lanes.origin.loaded && linesOf(lanes.origin) > linesOf(lanes.proxy)) ? lanes.origin : null)
    || lanes.proxy || lanes.origin;
  const alt = pick === lanes.proxy ? lanes.origin : lanes.proxy;
  const ev = pick && pick.evidence;
  const R = (state, reason, extra = {}) => ({ state, reason, lane_used: pick ? pick.lane : "none", ...extra });

  // 0. nothing loaded anywhere
  if ((!lanes.proxy || !lanes.proxy.loaded) && (!lanes.origin || !lanes.origin.loaded) && (!lanes.override || !lanes.override.loaded)) {
    return R("errored_reference", `navigation failed on every lane (${[lanes.proxy?.nav_error, lanes.origin?.nav_error].filter(Boolean).join(" · ") || "no lane loaded"})`);
  }
  if (!pick || !pick.loaded) return R("errored_reference", `primary lane failed to load: ${pick ? pick.nav_error : "missing"}`);

  const errText = ev?.error_text || "";
  const chunk404 = pick.network.chunk_404s.length;
  const apiFail = pick.network.api_failures.length;
  const cors = pick.cors_signals.length > 0;

  // 1. hard error page with no usable shell — never clean even if the rail renders
  if (errText && !shellOk(ev) && !hasData(ev?.data)) {
    return R("errored_reference", `reference renders an error page ("${errText}") without a usable shell`);
  }
  // 2. boot-killing missing chunks (js/css 404) with a broken/blank result
  if (chunk404 > 0 && (!shellOk(ev) || isBlank(ev))) {
    return R("missing_chunk", `${chunk404} chunk asset(s) 404 at the mirror and the app fails to boot`, { missing_chunks: pick.network.chunk_404s.map((c) => c.url.split("/").pop()) });
  }
  // 3. ORIGIN ALIGNMENT (the pipeline #38/#39 pattern): the standard /__apps proxy
  // lane carries no data while the capture-origin lane renders it — the reference
  // needs a reference_url_override onto the origin lane, nothing else is wrong.
  const proxyDefect = lanes.proxy && (!lanes.proxy.loaded
    ? `proxy lane fails to load (${lanes.proxy.nav_error})`
    : lanes.proxy.evidence?.error_text
      ? `proxy lane shows a failure ("${lanes.proxy.evidence.error_text}")${lanes.proxy.cors_signals.length ? " with CORS-blocked session lanes" : ""}`
      : !realData(lanes.proxy.evidence)
        ? `proxy lane renders no data (score ${dataScore(lanes.proxy?.evidence?.data)})`
        : "");
  const originBetter = !lanes.override && lanes.origin && lanes.origin.loaded
    && realData(lanes.origin.evidence) && !lanes.origin.evidence?.error_text && !!proxyDefect;
  if (originBetter) {
    const od = lanes.origin.evidence.data;
    return R("needs_origin_alignment", `${proxyDefect}, but the capture-origin lane (${CAPTURE_ORIGIN}) renders the app failure-free WITH data (rows ${od.table_rows}/${od.repeated_rows} · nodes ${od.graph_nodes} · cards ${od.cards} · lines ${od.meaningful_lines}) — align the reference URL like pipeline #38/#39`, { origin_lane_evidence: od, origin_lane_url: lanes.origin.url });
  }
  if (cors && !hasData(ev?.data) && !shellOk(ev)) {
    return R("cors_origin_mismatch", `CORS/origin failures block boot (${pick.cors_signals[0] || "cross-origin request failures"}) and no lane renders data`, { cors_evidence: pick.cors_signals });
  }
  // 3b. an app that never mounts with an uncaught page error is ERRORED, not blank/clean
  const pageErr = (pick.page_errors && pick.page_errors[0]) || (lanes.proxy && lanes.proxy.page_errors && lanes.proxy.page_errors[0]) || "";
  if (!realData(ev) && pageErr && ((ev?.data?.meaningful_lines | 0) < 8)) {
    return R("errored_reference", `the app never mounts — uncaught page error ("${pageErr.slice(0, 120)}")`, { page_error: pageErr.slice(0, 200) });
  }
  // 4. blank
  if (isBlank(ev)) {
    const why = chunk404 ? `blank body + ${chunk404} chunk 404s` : apiFail ? `blank body + ${apiFail} data-lane failures` : "blank body (no regions, no text)";
    return R(chunk404 ? "missing_chunk" : "blank_reference", why, chunk404 ? { missing_chunks: pick.network.chunk_404s.map((c) => c.url.split("/").pop()) } : {});
  }
  // 5. modal-only blocker: dismissing reveals real data without auth/origin change
  if (pick.modal && pick.modal.dismissed_reveals_data && hasData(ev?.data)) {
    return R("modal_blocked", "a blocking modal hides real data; dismissing it (Escape/portal-hide, no auth/origin change) reveals the data — wire a pre-capture hook like pipeline's", { modal_evidence: pick.modal });
  }
  // 6a. welcome/landing state masquerading as data: landing copy + card chrome but
  // ZERO row/node/repeated evidence is an EMPTY app home, not a data-clean reference.
  if (shellOk(ev) && hasData(ev?.data) && !realData(ev) && !errText) {
    return R("shell_clean_only", `shell renders a WELCOME/empty landing (cards ${ev.data.cards} · lines ${ev.data.meaningful_lines}, no row/node data) — clean chrome, no real data to port against${pick.lane === "origin" && proxyDefect ? ` (${proxyDefect}; the origin lane is the readable one)` : ""}`);
  }
  // 6. clean: shell + REAL data evidence (post any pre-capture/interaction)
  if (shellOk(ev) && realData(ev) && !errText) {
    return R("data_clean", `shell regions [${ev.regions.join(", ")}] + data evidence (rows ${ev.data.table_rows}/${ev.data.repeated_rows} · nodes ${ev.data.graph_nodes} · cards ${ev.data.cards} · lists ${ev.data.list_items} · lines ${ev.data.meaningful_lines})${pick.interaction ? ` — ${pick.interaction}` : ""}`);
  }
  // 7. shell renders but the body says the data failed
  if (shellOk(ev) && errText) {
    if (apiFail > 0) return R("needs_backend_reharvest", `shell boots but ${apiFail} data-lane request(s) fail at the capture ("${errText}") — the backend payloads were not harvested`, { api_failures: pick.network.api_failures.slice(0, 6) });
    return R("data_failed", `shell boots ${hasData(ev?.data) ? `with PARTIAL data (rows ${ev.data.table_rows}/${ev.data.repeated_rows} · nodes ${ev.data.graph_nodes} · cards ${ev.data.cards}) ` : ""}but the body reports a data failure ("${errText}") with captured (non-404) lanes`, {});
  }
  // 8. shell renders, no data, data lanes 404 → capture lacks backend payloads
  if (shellOk(ev) && !hasData(ev?.data)) {
    if (apiFail > 0) return R("needs_backend_reharvest", `shell boots empty and ${apiFail} data-lane request(s) 404/5xx at the capture — backend payloads missing`, { api_failures: pick.network.api_failures.slice(0, 6) });
    if ((ev.spinners || 0) > 0) return R("data_failed", `shell boots but data never arrives (${ev.spinners} live loading indicator(s), no failing lane recorded)`);
    return R("shell_clean_only", `shell regions [${ev.regions.join(", ")}] render clean but the body carries no real data (rows ${ev.data.table_rows}/${ev.data.repeated_rows} · nodes ${ev.data.graph_nodes} · cards ${ev.data.cards})`);
  }
  return R("unknown_blocked", `no classification rule matched (regions ${(ev?.regions || []).length}, dataScore ${dataScore(ev?.data)}, chunk404 ${chunk404}, apiFail ${apiFail}) — needs a human read`);
}

// ---- ranking: the directive's preference order ------------------------------
function rankNext(records) {
  const PORTED = new Set(["daemon_wired", "reference_ported"]);
  const candidates = records.filter((r) => !PORTED.has(r.parity_class) && r.clean_state === "data_clean");
  const OWNER_VALUE = { Data: 5, Ontology: 5, Governance: 5, Missions: 4, Automations: 4, Provenance: 4, Evaluations: 3, Foundry: 3, Studio: 3, Marketplace: 2, "Developer Console": 2, Workbench: 2, "Domain Apps": 2, Improvement: 3, Environments: 1 };
  const scored = candidates.map((r) => {
    const bindable = r.candidate_surface || r.substrate_surface ? 2 : 0; // daemon truth already wired/easy to bind
    const owner = OWNER_VALUE[r.owner] || 1;
    const grammarRisk = /table|list|catalog|inbox|registry|queue|wizard/i.test(r.grammar || "") ? 2 : /graph|canvas|map|spreadsheet|ide/i.test(r.grammar || "") ? 0 : 1; // low fabrication risk
    const ia = Math.min(2, Math.floor((r.landmarks_observed || []).length / 6)); // stable IA landmarks
    const noLive = 1; // local lanes only — the sweep never leaves the mirror
    const score = 10 + bindable * 3 + owner + grammarRisk * 2 + ia + noLive;
    return { slug: r.slug, owner: r.owner, score, why: {
      data_clean_reference: true,
      daemon_truth_bindable: bindable > 0 ? (r.candidate_surface || r.substrate_surface) : "no existing surface — new binding work",
      owner_value: `${r.owner} (${owner})`,
      fabrication_risk: grammarRisk === 2 ? `low (${r.grammar})` : grammarRisk === 0 ? `high (${r.grammar})` : `medium (${r.grammar})`,
      ia_landmarks: (r.landmarks_observed || []).slice(0, 8),
      live_palantir_dependency: "none (local mirror lanes only)",
    } };
  }).sort((a, b) => b.score - a.score);
  return scored.slice(0, 3).map((s, i) => ({ rank: i + 1, ...s }));
}

function contactSheet(records) {
  const cell = (r) => {
    const shots = (r.lanes_summary || []).filter((l) => l.screenshot).map((l) => `<figure><img src="${path.basename(l.screenshot)}" loading="lazy"><figcaption>${l.lane}</figcaption></figure>`).join("");
    return `<section class="${r.clean_state}"><h2>${r.slug} <small>${r.owner} · ${r.parity_class}</small></h2>
      <p class="state">${r.clean_state}</p><p class="why">${r.reason}</p>
      <p class="ev">rows ${r.data_evidence?.table_rows ?? "—"} · nodes ${r.data_evidence?.graph_nodes ?? "—"} · cards ${r.data_evidence?.cards ?? "—"} · lists ${r.data_evidence?.list_items ?? "—"} · lines ${r.data_evidence?.meaningful_lines ?? "—"}${r.error_text ? ` · <b>err:</b> ${r.error_text}` : ""}</p>
      <div class="shots">${shots}</div></section>`;
  };
  return `<!doctype html><meta charset="utf-8"><title>Reference clean sweep — 39 seeds</title><style>
  body{font:13px/1.45 system-ui;margin:16px;background:#14171b;color:#e8eaed}
  section{border:1px solid #2a2f36;border-radius:8px;padding:10px 12px;margin:0 0 12px;background:#1b1f24}
  h2{margin:0;font-size:15px} small{color:#8b93a0;font-weight:400}
  .state{font-weight:700;margin:4px 0} .why{color:#aeb6c2;margin:2px 0} .ev{color:#8b93a0;margin:2px 0}
  .data_clean .state{color:#43d17a}.shell_clean_only .state{color:#8ab4f8}
  .errored_reference .state,.data_failed .state{color:#f28b82}
  .blank_reference .state,.unknown_blocked .state{color:#9aa0a6}
  .missing_chunk .state,.needs_backend_reharvest .state{color:#fbbc04}
  .cors_origin_mismatch .state,.needs_origin_alignment .state{color:#d7aefb}.modal_blocked .state{color:#78d9ec}
  .shots{display:flex;gap:8px;margin-top:6px} figure{margin:0} img{width:420px;border:1px solid #2a2f36;border-radius:4px}
  figcaption{color:#8b93a0;font-size:11px;text-align:center}</style>
  <h1>Estate reference data-clean sweep — ${records.length} seeds</h1>${records.map(cell).join("\n")}`;
}

async function run() {
  mkdirSync(OUT, { recursive: true });
  const seeds = seedRows();
  const browser = await chromium.launch({ headless: true });
  const records = [];
  let cursor = 0;
  const worker = async () => {
    for (;;) {
      const i = cursor++; if (i >= seeds.length) return;
      const s = seeds[i];
      const pre = REFERENCE_PRE_CAPTURE[s.slug] || null;
      const lanes = {};
      lanes.proxy = await sweepLane(browser, `${SERVE}/__apps/${s.slug}`, s.slug, "proxy", pre, s.reference_landmarks);
      if (s.capture_base) lanes.origin = await sweepLane(browser, `${CAPTURE_ORIGIN}${s.capture_base}`, s.slug, "origin", pre, s.reference_landmarks);
      if (s.reference_url_override) lanes.override = await sweepLane(browser, s.reference_url_override, s.slug, "override", pre, s.reference_landmarks);
      const storeFacts = captureStoreFacts(s.capture_base);
      const cls = classify(s, lanes, storeFacts);
      const laneUsed = lanes[cls.lane_used === "proxy" ? "proxy" : cls.lane_used === "origin" ? "origin" : cls.lane_used === "override" ? "override" : "proxy"] || lanes.proxy;
      const ev = laneUsed && laneUsed.evidence;
      const rec = {
        slug: s.slug, owner: s.owner, parity_class: s.parity_class, grammar: s.grammar || "",
        reference_path: laneUsed ? laneUsed.url.replace(SERVE, "").replace(MIRROR, "") : `/__apps/${s.slug}`,
        candidate_surface: s.candidate_surface || null, substrate_surface: s.substrate_surface || null,
        clean_state: cls.state, reason: cls.reason, lane_used: cls.lane_used,
        shell_regions: (ev && ev.regions) || [],
        landmarks_observed: (ev && ev.landmarks) || [],
        matrix_landmarks_present: [], body_sample: "",
        data_evidence: (ev && ev.data) || null,
        error_text: (ev && ev.error_text) || "",
        missing_chunks: cls.missing_chunks || [],
        cors_evidence: cls.cors_evidence || (laneUsed ? laneUsed.cors_signals : []),
        modal_evidence: cls.modal_evidence || (laneUsed && laneUsed.modal) || null,
        capture_store: storeFacts,
        lanes_summary: Object.values(lanes).map((l) => ({
          lane: l.lane, url: l.url, loaded: l.loaded, nav_error: l.nav_error || "",
          regions: (l.evidence && l.evidence.regions) || [], data_score: dataScore(l.evidence && l.evidence.data),
          chunk_404s: l.network.chunk_404s.length, api_failures: l.network.api_failures.length,
          cross_origin_9225: l.network.cross_origin_9225, cors_signals: l.cors_signals.length,
          console_errors: l.console_errors.length, screenshot: l.screenshot,
        })),
        screenshot: (laneUsed && laneUsed.screenshot) || "",
      };
      if (laneUsed && laneUsed.evidence) {
        rec.matrix_landmarks_present = laneUsed.evidence.matrix_landmarks || [];
        rec.body_sample = laneUsed.evidence.body_sample || "";
      }
      writeFileSync(path.join(OUT, `${s.slug}-network.json`), JSON.stringify(Object.fromEntries(Object.entries(lanes).map(([k, l]) => [k, { url: l.url, network: l.network, console_errors: l.console_errors, page_errors: l.page_errors }])), null, 1));
      records.push(rec);
      console.log(`  ${String(records.length).padStart(2)}/${seeds.length}  ${s.slug.padEnd(14)} → ${cls.state.padEnd(24)} ${cls.reason.slice(0, 90)}`);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  await browser.close();
  records.sort((a, b) => seeds.findIndex((s) => s.slug === a.slug) - seeds.findIndex((s) => s.slug === b.slug));

  const ranked = rankNext(records);
  const byState = {};
  for (const r of records) byState[r.clean_state] = (byState[r.clean_state] || 0) + 1;
  const result = {
    schema: "ioi.hypervisor.reference-clean-sweep.v1",
    swept_at: new Date().toISOString(),
    serve: SERVE, mirror: MIRROR,
    total_seeds: records.length,
    by_state: byState,
    doctrine: "reference cleanliness only — no ports, no promotions, parity_class untouched; local mirror lanes only (no live dependency); screenshots corroborate, DOM/text/network classify",
    ranked_next: ranked,
    seeds: records,
    evidence_dir: path.relative(appRoot, OUT),
  };
  writeFileSync(path.join(OUT, "result.json"), JSON.stringify(result, null, 1));
  writeFileSync(path.join(OUT, "contact-sheet.html"), contactSheet(records));
  if (!ONLY.length) {
    // the COMMITTED compact evidence (screenshots stay in .artifacts)
    const compact = { ...result, seeds: records.map((r) => ({ ...r, lanes_summary: r.lanes_summary, capture_store: { ...r.capture_store, deep_route_dirs: r.capture_store.deep_route_dirs.slice(0, 6) } })) };
    writeFileSync(COMMITTED, JSON.stringify(compact, null, 1));
    console.log(`\n★ wrote reference-clean-sweep.json (committed evidence) + ${path.relative(appRoot, OUT)}/{result.json,contact-sheet.html}`);
  } else {
    console.log(`\n(partial sweep — committed file NOT written; artifact at ${path.relative(appRoot, OUT)}/result.json)`);
  }
  console.log(`states: ${JSON.stringify(byState)}`);
  console.log(`ranked next: ${ranked.map((r) => `#${r.rank} ${r.slug} (${r.score})`).join(" · ") || "(none data_clean among unported seeds)"}`);
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) run().catch((e) => { console.error("sweep crashed:", e); process.exit(1); });
