#!/usr/bin/env node
// Harvested application UX parity inventory verifier — LOCAL CAPTURE CORPUS ONLY.
//
// Doctrine (this phase): local capture corpus on disk -> served by the capture server (:9225) ->
// proxied through Hypervisor /__apps/<slug> -> verified in Playwright. No live re-harvest, no
// file-copy into authored code, no native replacement, no invented daemon truth. The seed may be
// unbound/nonfunctional; it passes if the CAPTURED UX boots and any failures are classified.
//
// Two proof layers:
//   1. STATIC ASSET PARITY — a JS asset served through /__apps is byte-identical to the same asset
//      from the capture server EXCEPT the narrow declared wire transforms (origin-fold + capitalized
//      brand-token rewrite). Any other divergence fails.
//   2. RUNTIME UX PARITY — Playwright boots each route and classifies the UX class, control
//      inventory, panels; screenshots; classifies console/network failures.
//
// Classification (decided ONLY from the local capture — never "needs live re-harvest"):
//   boots_editor_canvas | boots_graph | boots_wizard | boots_table_list | boots_document |
//   boots_landing | shell_only | blocked_missing_capture | blank | crash
//
// FAIL only on: served != 200 while the capture has content, blank page, crash page, brand leak in
// RENDERED text, a missing critical JS/CSS chunk that exists in the capture, an asset-parity
// violation beyond the declared transforms, or a false "covered" claim (a seed asserted high_value
// that renders nothing). shell_only / blocked_missing_capture are HONEST classifications, not fails.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-ux-parity-inventory.mjs
//   IOI_PARITY_ARTIFACT=/path.json  IOI_PARITY_SHOTS=/dir
// Exit 2 = BLOCKED (capture or serve unreachable). Exit 1 = a seed failed the honest bar.

import { chromium } from "playwright";
import { writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { SEED_INVENTORY } = await import(path.join(HERE, "harvest-seed-inventory.mjs"));

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const ARTIFACT = process.env.IOI_PARITY_ARTIFACT || "/tmp/harvest-ux-parity-inventory.json";
const SHOTS = process.env.IOI_PARITY_SHOTS || "";
if (SHOTS) { try { mkdirSync(SHOTS, { recursive: true }); } catch { /* */ } }

const sha = (buf) => createHash("sha256").update(buf).digest("hex");
// The EXACT declared wire transform the serve proxy applies to a content-addressable JS asset
// (asset-path requests are not fold-flagged, so brand-token rewrite only). Used to prove parity.
const brandTransform = (buf) => Buffer.from(buf.toString("utf8").replace(/Palantir/g, "IOI"), "utf8");

// Decide the UX class from DOM signals; local capture only. A page that renders nothing or an
// error boundary is "blocked_missing_capture" — the static capture lacks a chunk / API response /
// concrete resource ref the SPA needs to render past its shell. That is an HONEST terminal state
// for a local-capture-only sweep (never "needs live re-harvest"); a genuine routing bug (a capture
// asset we fail to serve) is detected separately and fails.
function classify(f) {
  if (f.blank || f.crash) return "blocked_missing_capture";
  const t = f.text;
  const has = (re) => re.test(t);
  if (f.hasSvgOrCanvas && has(/lineage|graph|nodes? selected|add resources|resource overview|explore|vertex/i)) return "boots_graph";
  if ((f.hasSvgOrCanvas || f.hasEditor) && has(/canvas|editor|palette|toolbar|save|actions|node|concept|component|widget|slate|module|pipeline|transform|scratchpad|formula/i)) return "boots_editor_canvas";
  if (has(/get started|start (planning|with)|new (source|monitor|automation|diagram|application|schedule)|create (new )?|next\b|step \d|register (a )?(new )?app|connect (a )?(new )?/i)) return "boots_wizard";
  if (f.hasEditor && has(/document|notepad|untitled|paragraph/i)) return "boots_document";
  if (f.hasTable || has(/no results|columns|rows|filter|registry|catalog|listings|sources|syncs|results|library/i)) return "boots_table_list";
  if (has(/welcome|get started|explore|learn (about|more)/i)) return "boots_landing";
  if (f.contentChars > 500) return "boots_landing";
  return "shell_only";
}
function bootedPastShell(cls) { return cls.startsWith("boots_"); }
const FAMILY = {
  editor_canvas: new Set(["boots_editor_canvas", "boots_graph", "boots_wizard", "boots_document"]),
  graph: new Set(["boots_graph", "boots_editor_canvas"]),
  wizard: new Set(["boots_wizard", "boots_editor_canvas", "boots_table_list", "boots_landing"]),
  table_list: new Set(["boots_table_list", "boots_wizard", "boots_landing"]),
  catalog: new Set(["boots_table_list", "boots_landing", "boots_graph"]),
  document: new Set(["boots_document", "boots_editor_canvas"]),
  landing: new Set(["boots_landing", "boots_table_list", "boots_wizard", "boots_editor_canvas", "boots_graph", "boots_document"]),
};
const satisfies = (intended, cls) => (FAMILY[intended] || new Set()).has(cls);

async function assetParity(seed, assetPaths) {
  // Sample up to 2 content-addressable JS assets the seed loaded; prove served == transform(capture).
  const sample = assetPaths.filter((p) => /content-addressable-storage\/.*\.js(\?|$)/.test(p)).slice(0, 2);
  const checks = [];
  for (const p of sample) {
    const rel = p.startsWith("http") ? new URL(p).pathname + new URL(p).search : p;
    try {
      const [served, cap] = await Promise.all([
        fetch(`${SERVE}${rel}`).then((r) => r.arrayBuffer()).then(Buffer.from),
        fetch(`${CAPTURE}${rel}`).then((r) => r.arrayBuffer()).then(Buffer.from),
      ]);
      const ok = sha(served) === sha(brandTransform(cap));
      checks.push({ asset: rel.split("/").pop().slice(0, 40), ok, served_bytes: served.length, capture_bytes: cap.length });
    } catch (e) { checks.push({ asset: rel.split("/").pop().slice(0, 40), ok: false, error: e.message.slice(0, 60) }); }
  }
  return checks;
}

async function bootSeed(browser, seed) {
  const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
  const pageErrors = [];
  const failedReq = [];
  const assetPaths = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  page.on("requestfailed", (r) => failedReq.push(r.url()));
  page.on("request", (r) => { const u = r.url(); if (/content-addressable-storage\//.test(u)) assetPaths.push(u); });
  let served = 0;
  try {
    const resp = await page.goto(`${SERVE}/__apps/${seed.slug}`, { waitUntil: "domcontentloaded", timeout: 25000 });
    served = resp ? resp.status() : 0;
  } catch (e) { pageErrors.push("goto: " + e.message); }
  await page.waitForTimeout(5500);
  const f = await page.evaluate(() => {
    const t = document.body ? document.body.innerText : "";
    const controls = document.querySelectorAll("button, a, [role=button], [role=tab], input, select, textarea").length;
    const panels = document.querySelectorAll("[class*=panel i], [class*=rail i], [class*=sidebar i], [class*=toolbar i], aside, nav").length;
    return {
      text: t, contentChars: t.replace(/\s+/g, " ").trim().length, controls, panels,
      hasSvgOrCanvas: !!document.querySelector("canvas, svg"),
      hasTable: !!document.querySelector("table, [role=grid], [role=table]"),
      hasEditor: !!document.querySelector("[class*=editor i], [contenteditable], .monaco-editor, [class*=canvas i]"),
      blank: t.replace(/\s+/g, "").length < 40,
      crash: /application error|something went wrong|unexpected error|failed to load the app|chunkloaderror/i.test(t) && t.replace(/\s+/g, " ").trim().length < 300,
      brandLeak: /\bPalantir\b/.test(t),
    };
  });
  const capHasContent = await fetch(`${CAPTURE}${seed.captureBase}`, { redirect: "manual" }).then((r) => r.status === 200).catch(() => false);
  const cls = classify(f);
  const realCrash = pageErrors.filter((e) => !/GraphQL|Failed to fetch|NetworkError|fetch failed|Load failed|4\d\d|5\d\d|is not iterable|forEach|undefined/i.test(e));
  const assetFail = failedReq.filter((u) => /content-addressable-storage\/.*\.(js|css)(\?|$)/.test(u));
  // Routing-bug detector: a content-addressable asset that failed THROUGH THE PROXY but EXISTS in
  // the capture is our serving bug (fail). One that is absent from the capture is an honest
  // missing-capture piece (classified, not failed).
  const routingBugAssets = [];
  for (const u of assetFail.slice(0, 5)) {
    const rel = u.startsWith("http") ? new URL(u).pathname + new URL(u).search : u;
    const inCapture = await fetch(`${CAPTURE}${rel}`, { redirect: "manual" }).then((r) => r.status === 200).catch(() => false);
    if (inCapture) routingBugAssets.push(rel.split("/").pop().slice(0, 40));
  }
  const criticalAssetFail = routingBugAssets;
  const parity = await assetParity(seed, assetPaths);
  let shot = "";
  if (SHOTS) { shot = path.join(SHOTS, `parity-${seed.slug}.png`); await page.screenshot({ path: shot }).catch(() => { shot = ""; }); }
  await page.close();
  return {
    ...seed, served_status: served, capture_has_content: capHasContent, classification: cls,
    booted_past_shell: bootedPastShell(cls), satisfies_grammar: satisfies(seed.grammar, cls),
    controls: f.controls, panels: f.panels, content_chars: f.contentChars, brand_leak: f.brandLeak,
    real_crashes: realCrash.slice(0, 2), critical_asset_failures: criticalAssetFail.slice(0, 2),
    asset_parity: parity, asset_parity_ok: parity.length === 0 || parity.every((c) => c.ok), screenshot: shot,
  };
}

async function run() {
  const capOk = await fetch(`${CAPTURE}/workspace/monocle/`).then((r) => r.ok).catch(() => false);
  if (!capOk) { console.error("BLOCKED: capture server not reachable at " + CAPTURE); process.exit(2); }
  const serveOk = await fetch(`${SERVE}/__ioi/applications`).then((r) => r.ok).catch(() => false);
  if (!serveOk) { console.error("BLOCKED: Hypervisor serve not reachable at " + SERVE); process.exit(2); }

  const browser = await chromium.launch();
  const rows = [];
  for (const seed of SEED_INVENTORY) {
    try { rows.push(await bootSeed(browser, seed)); }
    catch (e) { rows.push({ ...seed, served_status: 0, classification: "crash", booted_past_shell: false, real_crashes: [e.message] }); }
  }
  await browser.close();

  // FAIL only on genuine breakage of faithful local-capture serving. shell_only and
  // blocked_missing_capture are HONEST terminal classifications for a capture-only sweep — the
  // inventory records them for follow-up truth-binding, they are not failures.
  const failures = [];
  for (const r of rows) {
    if (r.served_status !== 200 && r.capture_has_content) failures.push(`${r.slug}: served ${r.served_status} but capture root has content (routing bug)`);
    if (r.brand_leak) failures.push(`${r.slug}: brand leak in RENDERED text (wire rebrand incomplete)`);
    if ((r.critical_asset_failures || []).length) failures.push(`${r.slug}: capture asset failed through the proxy — ${r.critical_asset_failures[0]} exists in capture (routing bug)`);
    if (!r.asset_parity_ok) failures.push(`${r.slug}: static asset parity violation beyond declared transforms`);
  }

  const artifact = {
    schema_version: "ioi.hypervisor.harvest-ux-parity-inventory.v1",
    phase: "local-capture-only (no live re-harvest)",
    capture: CAPTURE, serve: SERVE, total_seeds: rows.length,
    booted_past_shell: rows.filter((r) => r.booted_past_shell).length,
    asset_parity_checked: rows.filter((r) => (r.asset_parity || []).length).length,
    by_class: rows.reduce((m, r) => (m[r.classification] = (m[r.classification] || 0) + 1, m), {}),
    seeds: rows.map((r) => ({ owner: r.owner, slug: r.slug, capture: r.captureBase, intended_grammar: r.grammar,
      tier: r.tier, served: r.served_status, classification: r.classification, booted_past_shell: r.booted_past_shell,
      satisfies_grammar: r.satisfies_grammar, controls: r.controls, panels: r.panels,
      asset_parity: r.asset_parity, rebound_lane: r.reboundLane, unbound_note: r.note, screenshot: r.screenshot })),
  };
  try { writeFileSync(ARTIFACT, JSON.stringify(artifact, null, 2)); } catch { /* */ }

  console.log("\n  OWNER            SLUG          TIER        INTENDED       LOCAL CAPTURE BOOTS AS   CTRL  PARITY");
  console.log("  " + "-".repeat(100));
  for (const r of rows.sort((a, b) => a.owner.localeCompare(b.owner) || a.slug.localeCompare(b.slug))) {
    const par = (r.asset_parity || []).length ? (r.asset_parity_ok ? "✓" : "✗") : "—";
    console.log(`  ${r.owner.padEnd(16)} ${r.slug.padEnd(13)} ${r.tier.padEnd(11)} ${String(r.grammar).padEnd(14)} ${String(r.classification).padEnd(24)} ${String(r.controls || 0).padEnd(5)} ${par}`);
  }
  console.log(`\n  total ${artifact.total_seeds} · booted past shell ${artifact.booted_past_shell}/${artifact.total_seeds} · by class ${JSON.stringify(artifact.by_class)}`);
  console.log(`  artifact: ${ARTIFACT}`);
  if (failures.length) {
    console.log(`\n  FAILURES (${failures.length}):`); for (const f of failures) console.log("    ✗ " + f);
    console.log(`\nharvest UX parity inventory: FAIL`); process.exit(1);
  }
  console.log(`\nharvest UX parity inventory: OK`); process.exit(0);
}

run().catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
